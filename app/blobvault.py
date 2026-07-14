"""The blob vault: media payloads encrypted at rest, plus an encrypted index.

Same envelope discipline as the record vault, applied to files:
  - every media object is encrypted whole (AES-256-GCM, fresh nonce) into
    media/<object_id>.enc — its own DEK, wrapped by the same KeyReleaseClient
    seam (mock KMS locally, Cloud KMS on attestation in enclave mode);
  - one metadata line per object goes to media_index.jsonl.enc, encrypted
    the same way. Queries run over the INDEX; the payloads have
    no read path to any endpoint. open_object() exists only for the Mode C
    preview generator (Day 2), which runs inside the gate.

What the index deliberately does NOT store: the original filename. Only the
extension survives — filenames leak semantics ("site-B-nest-photos.zip").
"""
import base64
import hashlib
import json
import os
import uuid
from pathlib import Path
from typing import Dict, Iterator, Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .keyrelease import KeyReleaseClient
from .media import classify

_AAD_BLOB = b"ava-blob-v1"
_AAD_INDEX = b"ava-media-index-v1"

INDEX_FIELDS = {"object_id", "media_type", "mime", "ext", "size_bytes",
                "sha256_plain", "captured_at", "zone", "category", "quality"}


class BlobVault:
    def __init__(self, vault_dir: Path, key_release: KeyReleaseClient):
        self._dir = Path(vault_dir)
        self._media_dir = self._dir / "media"
        self._media_dir.mkdir(parents=True, exist_ok=True)
        self._index_path = self._dir / "media_index.jsonl.enc"
        self._wrapped_dek_path = self._dir / "dek.blob.wrapped"
        self._key_release = key_release
        self._dek = self._load_or_create_dek()

    def _load_or_create_dek(self) -> bytes:
        if self._wrapped_dek_path.exists():
            return self._key_release.unwrap_dek(self._wrapped_dek_path.read_bytes())
        dek = AESGCM.generate_key(bit_length=256)
        self._wrapped_dek_path.write_bytes(self._key_release.wrap_dek(dek))
        os.chmod(self._wrapped_dek_path, 0o600)
        return dek

    def put(self, payload: bytes, extension: str,
            zone: str, category: str, quality: str = "ok",
            captured_at: Optional[str] = None,
            media_type_override: Optional[str] = None) -> Dict:
        """Encrypt one media object + index it. Returns the index entry."""
        media_type, mime, ext = classify(extension, media_type_override)
        object_id = str(uuid.uuid4())

        aes = AESGCM(self._dek)
        nonce = os.urandom(12)
        # AAD binds ciphertext to its object_id: a swapped/renamed blob file
        # fails decryption instead of impersonating another object
        ct = aes.encrypt(nonce, payload, _AAD_BLOB + object_id.encode())
        (self._media_dir / f"{object_id}.enc").write_bytes(nonce + ct)

        entry = {
            "object_id": object_id,
            "media_type": media_type,
            "mime": mime,
            "ext": ext,
            "size_bytes": len(payload),
            "sha256_plain": hashlib.sha256(payload).hexdigest(),
            "captured_at": captured_at,
            "zone": zone,
            "category": category,
            "quality": quality,
        }
        self._append_index(entry)
        return entry

    def _append_index(self, entry: Dict) -> None:
        assert set(entry) == INDEX_FIELDS, f"index schema drift: {set(entry) ^ INDEX_FIELDS}"
        aes = AESGCM(self._dek)
        nonce = os.urandom(12)
        plaintext = json.dumps(entry, sort_keys=True, separators=(",", ":")).encode()
        ct = aes.encrypt(nonce, plaintext, _AAD_INDEX)
        with self._index_path.open("a") as f:
            f.write(json.dumps({
                "n": base64.b64encode(nonce).decode(),
                "c": base64.b64encode(ct).decode(),
            }) + "\n")

    def iter_index(self) -> Iterator[Dict]:
        """Decrypt index entries into memory — the query surface."""
        if not self._index_path.exists():
            return
        aes = AESGCM(self._dek)
        with self._index_path.open() as f:
            for line in f:
                blob = json.loads(line)
                nonce = base64.b64decode(blob["n"])
                ct = base64.b64decode(blob["c"])
                yield json.loads(aes.decrypt(nonce, ct, _AAD_INDEX))

    def open_object(self, object_id: str) -> bytes:
        """Decrypt one payload into memory. INTERNAL: the only legitimate
        caller is the Mode C preview generator (Day 2). No HTTP handler may
        call this — enforced by the leak tripwire tests, not just this comment."""
        path = self._media_dir / f"{object_id}.enc"
        if not path.exists():
            raise KeyError(f"no such object: {object_id}")
        raw = path.read_bytes()
        return AESGCM(self._dek).decrypt(raw[:12], raw[12:], _AAD_BLOB + object_id.encode())

    def object_count(self) -> int:
        return sum(1 for _ in self._media_dir.glob("*.enc"))
