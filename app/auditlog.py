"""Tamper-evident audit log: hash-chained, Ed25519-signed, append-only.

Every entry commits to the previous one (prev_hash), and every entry is
signed by the gate's audit key. Change any historical line and the chain
breaks; forge a line and the signature fails. verify_chain() proves both.

In enclave mode the signing key is generated inside the TEE at first boot,
so a valid signature is also evidence the entry was written by the attested
workload. Swap target for v2: anchor entry hashes to a transparency log
(e.g. Sigstore Rekor) for third-party timestamping.
"""
import base64
import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Tuple

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey)

_GENESIS = "0" * 64


def _canonical(entry: dict) -> bytes:
    return json.dumps(entry, sort_keys=True, separators=(",", ":")).encode()


class AuditLog:
    def __init__(self, path: Path, keys_dir: Path):
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._key = self._load_or_create_key(Path(keys_dir))
        self._last_seq, self._last_hash = self._read_tail()

    @staticmethod
    def _load_or_create_key(keys_dir: Path) -> Ed25519PrivateKey:
        priv_path = keys_dir / "audit_signing.key"
        pub_path = keys_dir / "audit_signing.pub"
        if priv_path.exists():
            return serialization.load_pem_private_key(
                priv_path.read_bytes(), password=None)
        keys_dir.mkdir(parents=True, exist_ok=True)
        key = Ed25519PrivateKey.generate()
        priv_path.write_bytes(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()))
        os.chmod(priv_path, 0o600)
        # public half is shared with anyone who needs to verify the log
        pub_path.write_bytes(key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo))
        return key

    def _read_tail(self) -> Tuple[int, str]:
        if not self._path.exists():
            return 0, _GENESIS
        last = None
        with self._path.open() as f:
            for line in f:
                if line.strip():
                    last = line
        if last is None:
            return 0, _GENESIS
        entry = json.loads(last)
        return entry["seq"], entry["entry_hash"]

    def append(self, consumer_id: str, query: dict, answer: dict) -> dict:
        body = {
            "seq": self._last_seq + 1,
            "ts": datetime.now(timezone.utc).isoformat(),
            "consumer_id": consumer_id,
            "query": query,
            "answer_sha256": hashlib.sha256(_canonical(answer)).hexdigest(),
            "prev_hash": self._last_hash,
        }
        entry_hash = hashlib.sha256(_canonical(body)).hexdigest()
        sig = self._key.sign(bytes.fromhex(entry_hash)).hex()
        entry = dict(body, entry_hash=entry_hash, sig=sig)
        with self._path.open("a") as f:
            f.write(json.dumps(entry, sort_keys=True, separators=(",", ":")) + "\n")
        self._last_seq, self._last_hash = entry["seq"], entry_hash
        return entry


def public_key_fingerprint(pem: bytes) -> str:
    """SHA-256 over the DER body of a PEM public key — stable across PEM
    whitespace/armor differences, and computable with only the stdlib (the
    consumer kit reimplements exactly this, without `cryptography`)."""
    body = b"".join(line for line in pem.splitlines()
                    if line and not line.startswith(b"-----"))
    return hashlib.sha256(base64.b64decode(body)).hexdigest()


def verify_chain(path: Path, public_key_pem: bytes) -> Tuple[bool, Optional[int]]:
    """Walk the log; return (ok, first_bad_seq). Verifies hash chain + signatures."""
    pub = serialization.load_pem_public_key(public_key_pem)
    assert isinstance(pub, Ed25519PublicKey)
    prev_hash = _GENESIS
    expected_seq = 1
    path = Path(path)
    if not path.exists():
        return True, None
    with path.open() as f:
        for line in f:
            if not line.strip():
                continue
            entry = json.loads(line)
            seq = entry.get("seq")
            body = {k: v for k, v in entry.items() if k not in ("entry_hash", "sig")}
            if seq != expected_seq or entry.get("prev_hash") != prev_hash:
                return False, seq
            if hashlib.sha256(_canonical(body)).hexdigest() != entry["entry_hash"]:
                return False, seq
            try:
                pub.verify(bytes.fromhex(entry["sig"]), bytes.fromhex(entry["entry_hash"]))
            except Exception:
                return False, seq
            prev_hash = entry["entry_hash"]
            expected_seq += 1
    return True, None
