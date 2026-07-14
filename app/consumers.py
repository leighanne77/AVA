"""Consumer key registry: issue, authenticate, revoke.

v1 keys are bearer tokens, stored only as SHA-256 hashes, revocable per
consumer. The registry file is re-read when it changes on disk, so a CLI
revocation takes effect on the running gate within one request.

Upgrade path: bearer token → hardware-bound client
certificate → mutual attestation. The gate's auth seam is this module.
"""
import hashlib
import hmac
import json
import secrets
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


def _hash_key(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class ConsumerRegistry:
    def __init__(self, path: Path):
        self._path = Path(path)
        self._mtime = None
        self._consumers = {}
        self._load()

    def _load(self) -> None:
        if self._path.exists():
            self._consumers = json.loads(self._path.read_text()).get("consumers", {})
            self._mtime = self._path.stat().st_mtime
        else:
            self._consumers = {}
            self._mtime = None

    def _reload_if_changed(self) -> None:
        mtime = self._path.stat().st_mtime if self._path.exists() else None
        if mtime != self._mtime:
            self._load()

    def _save(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._path.write_text(json.dumps({"consumers": self._consumers}, indent=2))
        self._mtime = self._path.stat().st_mtime

    def issue(self, consumer_id: str, label: str = "",
              trusted: bool = False) -> str:
        """Create a consumer and return its key — shown exactly once.
        `trusted` gates commitment queries (attest): commitments reveal
        dataset size/shape over time, so they are an owner-granted
        privilege, OFF by default."""
        self._reload_if_changed()
        if consumer_id in self._consumers:
            raise ValueError(f"consumer '{consumer_id}' already exists")
        key = "ava_" + secrets.token_urlsafe(32)
        self._consumers[consumer_id] = {
            "key_sha256": _hash_key(key),
            "status": "active",
            "trusted": bool(trusted),
            "label": label,
            "issued_at": _now(),
            "revoked_at": None,
        }
        self._save()
        return key

    def authenticate(self, presented_key: str) -> Optional[dict]:
        """Return {'consumer_id', 'status', 'trusted'} for a known key,
        else None. Status may be 'revoked' — the gate decides 401 vs 403.
        Entries issued before the trusted flag existed default to False:
        privileges are opted into, never inherited."""
        self._reload_if_changed()
        presented_hash = _hash_key(presented_key)
        for cid, entry in self._consumers.items():
            if hmac.compare_digest(entry["key_sha256"], presented_hash):
                return {"consumer_id": cid, "status": entry["status"],
                        "trusted": bool(entry.get("trusted", False))}
        return None

    def set_trusted(self, consumer_id: str, trusted: bool) -> bool:
        """Owner-side switch for the attest privilege; like revocation,
        it bites on the running gate within one request (mtime reload)."""
        self._reload_if_changed()
        entry = self._consumers.get(consumer_id)
        if entry is None:
            return False
        entry["trusted"] = bool(trusted)
        self._save()
        return True

    def revoke(self, consumer_id: str) -> bool:
        self._reload_if_changed()
        entry = self._consumers.get(consumer_id)
        if not entry or entry["status"] == "revoked":
            return False
        entry["status"] = "revoked"
        entry["revoked_at"] = _now()
        self._save()
        return True

    def list_consumers(self) -> dict:
        """Metadata only — never key material."""
        self._reload_if_changed()
        return {
            cid: {k: v for k, v in e.items() if k != "key_sha256"}
            for cid, e in self._consumers.items()
        }
