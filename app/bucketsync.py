"""Vault ↔ bucket sync — the ciphertext vault's home is Cloud Storage.

Scope is structural, not filtered: ONLY the vault directory is walked, and
everything in it is safe to leave the machine by construction — encrypted
records/media (*.enc) and KMS-wrapped DEKs. The things that must stay
owner-side or gate-side (consumer registry, grants, audit log, signing
keys, the watermark master key) live OUTSIDE vault_dir and are therefore
unreachable by this module. tests/test_cloud_release.py trips if that
boundary ever moves.

Flow: the owner ingests locally and pushes; the enclave gate pulls at boot
(wired in this layer). Credentials follow the same rule as key release —
ADC on the owner's machine, attested workload identity in the enclave, no
key files anywhere.
"""
from pathlib import Path
from typing import List, Optional

BUCKET_PREFIX = "vault/"


def _client(client=None):
    if client is not None:
        return client
    from google.cloud import storage  # deferred: local mode never imports it
    return storage.Client()


def local_files(vault_dir: Path) -> List[str]:
    """Relative paths of every file under vault_dir — the sync set."""
    vault_dir = Path(vault_dir)
    return sorted(str(p.relative_to(vault_dir))
                  for p in vault_dir.rglob("*") if p.is_file())


def push(vault_dir: Path, bucket_name: str, client=None) -> List[str]:
    """Upload the vault to gs://bucket/vault/…; returns pushed rel paths."""
    vault_dir = Path(vault_dir)
    bucket = _client(client).bucket(bucket_name)
    pushed = []
    for rel in local_files(vault_dir):
        bucket.blob(BUCKET_PREFIX + rel).upload_from_filename(
            str(vault_dir / rel))
        pushed.append(rel)
    return pushed


def pull(bucket_name: str, vault_dir: Path, client=None) -> List[str]:
    """Download gs://bucket/vault/… into vault_dir; returns pulled rel paths."""
    vault_dir = Path(vault_dir)
    vault_dir.mkdir(parents=True, exist_ok=True)
    pulled = []
    for blob in _client(client).list_blobs(bucket_name, prefix=BUCKET_PREFIX):
        rel = blob.name[len(BUCKET_PREFIX):]
        if not rel:
            continue
        dest = (vault_dir / rel).resolve()
        if not str(dest).startswith(str(vault_dir.resolve())):
            raise ValueError(f"refusing path escape: {blob.name}")
        dest.parent.mkdir(parents=True, exist_ok=True)
        blob.download_to_filename(str(dest))
        pulled.append(rel)
    return pulled
