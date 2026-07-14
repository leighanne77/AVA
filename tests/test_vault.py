"""The vault: plaintext never on disk, ciphertext round-trips, DEK stays wrapped."""
from pathlib import Path

from app.keyrelease import LocalMockKMS
from app.vault import Vault

from conftest import KNOWN_RECORDS, SECRET_MARKERS


def _all_disk_bytes(directory: Path) -> bytes:
    out = b""
    for p in sorted(directory.rglob("*")):
        if p.is_file():
            out += p.read_bytes()
    return out


def test_roundtrip(loaded_vault):
    records = list(loaded_vault.iter_records())
    assert len(records) == len(KNOWN_RECORDS)
    assert sorted(r["id"] for r in records) == sorted(r["id"] for r in KNOWN_RECORDS)


def test_no_plaintext_on_disk(settings, loaded_vault):
    disk = _all_disk_bytes(settings.data_dir)
    for marker in SECRET_MARKERS:
        assert marker.encode() not in disk, f"plaintext '{marker}' leaked to disk"


def test_dek_is_wrapped_not_raw(settings, loaded_vault):
    wrapped = (settings.vault_dir / "dek.wrapped").read_bytes()
    # the raw DEK must not equal what's on disk (it's nonce+ciphertext, longer than 32B)
    assert len(wrapped) > 32
    assert loaded_vault._dek not in wrapped


def test_reopen_with_same_kms_decrypts(settings, loaded_vault):
    vault2 = Vault(settings.vault_dir, LocalMockKMS(settings.keys_dir))
    assert len(list(vault2.iter_records())) == len(KNOWN_RECORDS)


def test_wrong_key_cannot_open(settings, loaded_vault, tmp_path):
    import pytest
    from app.keyrelease import KeyReleaseError
    with pytest.raises(KeyReleaseError):
        Vault(settings.vault_dir, LocalMockKMS(tmp_path / "other-keys"))


def test_rejects_unknown_fields(settings):
    import pytest
    vault = Vault(settings.vault_dir, LocalMockKMS(settings.keys_dir))
    with pytest.raises(ValueError):
        vault.ingest([{"id": "x", "surprise": 1}])
