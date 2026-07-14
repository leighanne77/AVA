"""The evidence vault: records encrypted at rest, decrypted only in memory.

Envelope encryption:
  - One 256-bit DEK (data-encryption key) encrypts every record with
    AES-256-GCM, a fresh nonce per record.
  - The DEK itself is stored only WRAPPED by the KeyReleaseClient
    (mock KMS locally; Cloud KMS gated on attestation in enclave mode).
  - Plaintext exists nowhere on disk — only ciphertext JSONL plus the
    wrapped DEK. Decryption happens in this process's memory, per query.
"""
import base64
import json
import os
from pathlib import Path
from typing import Dict, Iterator, List

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .keyrelease import KeyReleaseClient

_AAD = b"ava-vault-record-v1"

RECORD_FIELDS = {"id", "ts", "category", "zone", "value", "quality"}


class Vault:
    def __init__(self, vault_dir: Path, key_release: KeyReleaseClient):
        self._dir = Path(vault_dir)
        self._dir.mkdir(parents=True, exist_ok=True)
        self._records_path = self._dir / "records.jsonl.enc"
        self._wrapped_dek_path = self._dir / "dek.wrapped"
        self._key_release = key_release
        self._dek = self._load_or_create_dek()

    def _load_or_create_dek(self) -> bytes:
        if self._wrapped_dek_path.exists():
            return self._key_release.unwrap_dek(self._wrapped_dek_path.read_bytes())
        dek = AESGCM.generate_key(bit_length=256)
        self._wrapped_dek_path.write_bytes(self._key_release.wrap_dek(dek))
        os.chmod(self._wrapped_dek_path, 0o600)
        return dek

    def ingest(self, records: List[Dict]) -> int:
        """Encrypt and append records. Returns count ingested."""
        aes = AESGCM(self._dek)
        lines = []
        for rec in records:
            unknown = set(rec) - RECORD_FIELDS
            if unknown:
                raise ValueError(f"unknown record fields: {unknown}")
            plaintext = json.dumps(rec, sort_keys=True, separators=(",", ":")).encode()
            nonce = os.urandom(12)
            ct = aes.encrypt(nonce, plaintext, _AAD)
            lines.append(json.dumps({
                "n": base64.b64encode(nonce).decode(),
                "c": base64.b64encode(ct).decode(),
            }))
        with self._records_path.open("a") as f:
            for line in lines:
                f.write(line + "\n")
        return len(lines)

    def iter_records(self) -> Iterator[Dict]:
        """Decrypt records into memory, one at a time. Never returned to consumers —
        only aggregates computed from them leave the gate (see queries.py)."""
        if not self._records_path.exists():
            return
        aes = AESGCM(self._dek)
        with self._records_path.open() as f:
            for line in f:
                blob = json.loads(line)
                nonce = base64.b64decode(blob["n"])
                ct = base64.b64decode(blob["c"])
                yield json.loads(aes.decrypt(nonce, ct, _AAD))

    def record_count(self) -> int:
        if not self._records_path.exists():
            return 0
        with self._records_path.open() as f:
            return sum(1 for _ in f)
