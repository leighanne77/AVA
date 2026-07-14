"""Key release — the swappable seam between local dev and the attested enclave.

The vault never touches the key-encryption key (KEK) directly. It hands its
data-encryption key (DEK) to a KeyReleaseClient to wrap/unwrap. Which client
is wired in decides the trust model:

  LocalMockKMS        — dev only. KEK is a local file. No protection claimed.
  CloudKMSKeyRelease  — v1 production. The KEK lives in Cloud KMS and is only
                        usable by the attested workload identity (the release
                        policy names the container's image digest — see
                        scripts/gcp/04_workload_identity.sh). Google admins,
                        the operator, and any non-attested code get nothing.

This interface is deliberately shaped like the Confidential Containers
Trustee KBS contract so the AVA v2 (open-source) swap is a client change,
not a redesign.
"""
import os
from abc import ABC, abstractmethod
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_AAD = b"ava-dek-wrap-v1"


class KeyReleaseError(Exception):
    pass


class KeyReleaseClient(ABC):
    @abstractmethod
    def wrap_dek(self, dek: bytes) -> bytes: ...

    @abstractmethod
    def unwrap_dek(self, wrapped: bytes) -> bytes: ...

    @abstractmethod
    def describe(self) -> dict: ...


class LocalMockKMS(KeyReleaseClient):
    """Simulates KMS wrap/unwrap with a KEK on local disk. DEV ONLY."""

    def __init__(self, keys_dir: Path):
        self._kek_path = Path(keys_dir) / "mock_kek.bin"
        if not self._kek_path.exists():
            self._kek_path.parent.mkdir(parents=True, exist_ok=True)
            self._kek_path.write_bytes(AESGCM.generate_key(bit_length=256))
            os.chmod(self._kek_path, 0o600)
        self._kek = self._kek_path.read_bytes()

    def wrap_dek(self, dek: bytes) -> bytes:
        nonce = os.urandom(12)
        return nonce + AESGCM(self._kek).encrypt(nonce, dek, _AAD)

    def unwrap_dek(self, wrapped: bytes) -> bytes:
        try:
            return AESGCM(self._kek).decrypt(wrapped[:12], wrapped[12:], _AAD)
        except Exception as exc:
            raise KeyReleaseError(f"mock KMS unwrap failed: {exc}") from exc

    def describe(self) -> dict:
        return {"client": "LocalMockKMS", "trust": "none — development only"}


class CloudKMSKeyRelease(KeyReleaseClient):
    """v1 production client: wrap/unwrap via Cloud KMS encrypt/decrypt.

    The KEK never exists in this process — every wrap/unwrap is an RPC to
    Cloud KMS, and KMS answers only if the caller's identity satisfies the
    owner's release policy (04_workload_identity.sh pins it to the attested
    image digest). No service-account key files, ever: inside Confidential
    Space credentials come from the attested workload identity; on the
    owner's admin machine they come from gcloud ADC.

    The client is created lazily so constructing the object (e.g. at app
    wiring time, or in tests) never touches the network or credentials.
    """

    def __init__(self, kms_key_name: str, client=None):
        if not kms_key_name:
            raise KeyReleaseError(
                "enclave mode requires AVA_KMS_KEY_NAME "
                "(projects/…/locations/…/keyRings/…/cryptoKeys/…)")
        self._key_name = kms_key_name
        self._client = client  # injectable for tests; lazy otherwise

    def _kms(self):
        if self._client is None:
            from google.cloud import kms  # deferred: local mode never imports it
            self._client = kms.KeyManagementServiceClient()
        return self._client

    def wrap_dek(self, dek: bytes) -> bytes:
        try:
            resp = self._kms().encrypt(request={
                "name": self._key_name,
                "plaintext": dek,
                "additional_authenticated_data": _AAD,
            })
        except Exception as exc:
            raise KeyReleaseError(f"Cloud KMS wrap failed: {exc}") from exc
        return resp.ciphertext

    def unwrap_dek(self, wrapped: bytes) -> bytes:
        try:
            resp = self._kms().decrypt(request={
                "name": self._key_name,
                "ciphertext": wrapped,
                "additional_authenticated_data": _AAD,
            })
        except Exception as exc:
            # covers both transport errors and KMS refusals (bad identity,
            # disabled key, flipped release policy) — the owner's switch
            raise KeyReleaseError(f"Cloud KMS refused to unwrap: {exc}") from exc
        return resp.plaintext

    def describe(self) -> dict:
        return {"client": "CloudKMSKeyRelease", "key": self._key_name,
                "trust": "KEK in Cloud KMS — released only to identities "
                         "satisfying the owner's release policy"}


def make_key_release(settings) -> KeyReleaseClient:
    if settings.mode == "enclave":
        return CloudKMSKeyRelease(settings.kms_key_name)
    return LocalMockKMS(settings.keys_dir)
