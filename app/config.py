"""Runtime settings for the AVA query gate.

Two modes:
  local   — development: mock key release, keys on local disk.
  enclave — production target: Cloud KMS key release gated on attestation,
            running inside a Confidential Space TEE.
"""
import os
from dataclasses import dataclass, field
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent


@dataclass
class Settings:
    mode: str = "local"                      # "local" | "enclave"
    data_dir: Path = _REPO_ROOT / "data"
    keys_dir: Path = _REPO_ROOT / "keys"
    # enclave-mode targets, unused in local mode
    kms_key_name: str = ""                   # projects/.../cryptoKeys/ava-vault-kek
    vault_bucket: str = ""                   # GCS bucket holding the ciphertext vault

    vault_dir: Path = field(init=False)
    registry_path: Path = field(init=False)
    grants_path: Path = field(init=False)
    audit_path: Path = field(init=False)

    def __post_init__(self):
        self.data_dir = Path(self.data_dir)
        self.keys_dir = Path(self.keys_dir)
        self.vault_dir = self.data_dir / "vault"
        self.registry_path = self.data_dir / "consumers.json"
        self.grants_path = self.data_dir / "grants.json"
        self.audit_path = self.data_dir / "audit.jsonl"

    @classmethod
    def from_env(cls) -> "Settings":
        return cls(
            mode=os.environ.get("AVA_MODE", "local"),
            data_dir=Path(os.environ.get("AVA_DATA_DIR", _REPO_ROOT / "data")),
            keys_dir=Path(os.environ.get("AVA_KEYS_DIR", _REPO_ROOT / "keys")),
            kms_key_name=os.environ.get("AVA_KMS_KEY_NAME", ""),
            vault_bucket=os.environ.get("AVA_VAULT_BUCKET", ""),
        )

    def ensure_dirs(self) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.vault_dir.mkdir(parents=True, exist_ok=True)
        self.keys_dir.mkdir(parents=True, exist_ok=True)
