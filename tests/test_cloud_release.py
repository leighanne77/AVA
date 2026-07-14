"""real key release + vault-in-bucket.

Unit layer: CloudKMSKeyRelease against a fake KMS (no network in tests —
the REAL KMS is exercised by the live smoke and, later, the enclave).
Boundary layer: the bucket sync's scope invariant — only vault_dir
(ciphertext + wrapped DEKs) can ever leave the machine.
"""
import pytest

from app import bucketsync
from app.config import Settings
from app.keyrelease import (CloudKMSKeyRelease, KeyReleaseError,
                            make_key_release)
from app.vault import Vault


class FakeKMSResponse:
    def __init__(self, data):
        self.ciphertext = data
        self.plaintext = data


class FakeKMS:
    """Mimics KeyManagementServiceClient.encrypt/decrypt: reversible
    transform, records the requests so AAD/key usage can be asserted."""

    def __init__(self):
        self.requests = []

    def encrypt(self, request):
        self.requests.append(("encrypt", request))
        return FakeKMSResponse(b"WRAPPED:" + bytes(reversed(request["plaintext"])))

    def decrypt(self, request):
        self.requests.append(("decrypt", request))
        ct = request["ciphertext"]
        if not ct.startswith(b"WRAPPED:"):
            raise RuntimeError("permission denied / malformed")
        return FakeKMSResponse(bytes(reversed(ct[len(b"WRAPPED:"):])))


KEY_NAME = "projects/p/locations/l/keyRings/r/cryptoKeys/k"


def test_wrap_unwrap_roundtrip_and_aad():
    fake = FakeKMS()
    kr = CloudKMSKeyRelease(KEY_NAME, client=fake)
    dek = bytes(range(32))
    assert kr.unwrap_dek(kr.wrap_dek(dek)) == dek
    for _, req in fake.requests:
        assert req["name"] == KEY_NAME
        assert req["additional_authenticated_data"] == b"ava-dek-wrap-v1"


def test_kms_refusal_is_a_key_release_error():
    """A KMS 'no' (revoked policy, disabled key, wrong identity) must
    surface as KeyReleaseError — the owner's switch, not a crash."""
    kr = CloudKMSKeyRelease(KEY_NAME, client=FakeKMS())
    with pytest.raises(KeyReleaseError):
        kr.unwrap_dek(b"not-something-kms-wrapped")


def test_vault_runs_on_cloud_kms_seam(tmp_path):
    """The whole vault works over the CloudKMS client — same seam, no
    code path differences beyond the constructor."""
    kr = CloudKMSKeyRelease(KEY_NAME, client=FakeKMS())
    vault = Vault(tmp_path / "vault", kr)
    vault.ingest([{"id": "r1", "ts": "2026-01-01", "category": "alpha",
                   "zone": "zone-01", "value": 1.0, "quality": "ok"}])
    # a fresh Vault instance must unwrap the persisted DEK via KMS
    vault2 = Vault(tmp_path / "vault", CloudKMSKeyRelease(KEY_NAME, client=FakeKMS()))
    assert [r["id"] for r in vault2.iter_records()] == ["r1"]


def test_enclave_mode_requires_key_name():
    with pytest.raises(KeyReleaseError):
        CloudKMSKeyRelease("")


def test_make_key_release_is_lazy_in_enclave_mode(tmp_path):
    """Wiring the app in enclave mode must not touch network/credentials —
    the KMS client is created on first use, not at construction."""
    s = Settings(mode="enclave", data_dir=tmp_path / "d", keys_dir=tmp_path / "k",
                 kms_key_name=KEY_NAME)
    kr = make_key_release(s)
    assert isinstance(kr, CloudKMSKeyRelease)
    assert kr.describe()["key"] == KEY_NAME  # describe() is offline too


# ---------- bucket sync: the boundary that must never move ----------

def test_sync_scope_is_vault_dir_only(settings, loaded_vault):
    """THE boundary tripwire: the sync set contains ciphertext and wrapped
    DEKs — never registries, grants, audit log, or any key material."""
    # make the owner-side state exist alongside the vault
    settings.registry_path.write_text("{}")
    settings.grants_path.write_text("{}")
    settings.audit_path.write_text("")
    (settings.keys_dir / "audit_signing.key").write_bytes(b"x")

    files = bucketsync.local_files(settings.vault_dir)
    assert files, "vault should not be empty in this test"
    for rel in files:
        assert rel.endswith(".enc") or rel.endswith(".wrapped"), \
            f"unexpected file class in sync set: {rel}"
    joined = " ".join(files)
    for banned in ("consumers.json", "grants.json", "audit.jsonl",
                   "audit_signing", "watermark.key", "mock_kek"):
        assert banned not in joined


class FakeBlob:
    def __init__(self, name, store):
        self.name, self._store = name, store

    def upload_from_filename(self, path):
        from pathlib import Path
        self._store[self.name] = Path(path).read_bytes()

    def download_to_filename(self, path):
        from pathlib import Path
        Path(path).write_bytes(self._store[self.name])


class FakeBucket:
    def __init__(self, store):
        self._store = store

    def blob(self, name):
        return FakeBlob(name, self._store)


class FakeStorage:
    def __init__(self):
        self.store = {}

    def bucket(self, name):
        return FakeBucket(self.store)

    def list_blobs(self, name, prefix=""):
        return [FakeBlob(n, self.store) for n in sorted(self.store)
                if n.startswith(prefix)]


def test_push_pull_roundtrip(settings, loaded_vault, tmp_path):
    fake = FakeStorage()
    pushed = bucketsync.push(settings.vault_dir, "b", client=fake)
    assert "records.jsonl.enc" in pushed and "dek.wrapped" in pushed
    assert all(k.startswith(bucketsync.BUCKET_PREFIX) for k in fake.store)

    dest = tmp_path / "restored"
    pulled = bucketsync.pull("b", dest, client=fake)
    assert sorted(pulled) == sorted(pushed)
    for rel in pulled:
        assert (dest / rel).read_bytes() == (settings.vault_dir / rel).read_bytes()


def test_pull_refuses_path_escape(tmp_path):
    fake = FakeStorage()
    fake.store[bucketsync.BUCKET_PREFIX + "../evil"] = b"x"
    with pytest.raises(ValueError):
        bucketsync.pull("b", tmp_path / "v", client=fake)
