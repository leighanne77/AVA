"""Sample grants — the owner's leash on Mode C previews.

A grant says: THIS consumer may preview objects matching THESE filters
until THIS moment. Issued and revoked owner-side only (CLI, never HTTP).
Expiry is enforced server-side on every request; like consumer keys, the
registry file is re-read on change, so a CLI revocation bites within one
request.
"""
import json
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, Optional

GRANT_FILTER_KEYS = ("media_type", "zone", "category", "ts_from", "ts_to")


class GrantError(Exception):
    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(reason)


def _now() -> datetime:
    return datetime.now(timezone.utc)


class GrantRegistry:
    def __init__(self, path: Path):
        self._path = Path(path)
        self._mtime = None
        self._grants: Dict[str, dict] = {}
        self._load()

    def _load(self) -> None:
        if self._path.exists():
            self._grants = json.loads(self._path.read_text()).get("grants", {})
            self._mtime = self._path.stat().st_mtime
        else:
            self._grants, self._mtime = {}, None

    def _reload_if_changed(self) -> None:
        mtime = self._path.stat().st_mtime if self._path.exists() else None
        if mtime != self._mtime:
            self._load()

    def _save(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._path.write_text(json.dumps({"grants": self._grants}, indent=2))
        self._mtime = self._path.stat().st_mtime

    def issue(self, consumer_id: str, filters: Dict, ttl_hours: float) -> str:
        self._reload_if_changed()
        unknown = set(filters) - set(GRANT_FILTER_KEYS)
        if unknown:
            raise ValueError(f"unknown grant filter(s): {unknown}")
        grant_id = str(uuid.uuid4())
        self._grants[grant_id] = {
            "consumer_id": consumer_id,
            "filters": {k: v for k, v in filters.items() if v is not None},
            "issued_at": _now().isoformat(),
            "expires_at": (_now() + timedelta(hours=ttl_hours)).isoformat(),
            "status": "active",
            "revoked_at": None,
        }
        self._save()
        return grant_id

    def check(self, grant_id: str, consumer_id: str) -> dict:
        """Return the grant if it is live and belongs to this consumer;
        raise GrantError(reason) otherwise. Reasons: unknown, not_yours,
        revoked, expired."""
        self._reload_if_changed()
        grant = self._grants.get(grant_id)
        if grant is None:
            raise GrantError("unknown")
        if grant["consumer_id"] != consumer_id:
            raise GrantError("not_yours")
        if grant["status"] != "active":
            raise GrantError("revoked")
        if _now().isoformat() > grant["expires_at"]:
            raise GrantError("expired")
        return grant

    def revoke(self, grant_id: str) -> bool:
        self._reload_if_changed()
        grant = self._grants.get(grant_id)
        if not grant or grant["status"] == "revoked":
            return False
        grant["status"] = "revoked"
        grant["revoked_at"] = _now().isoformat()
        self._save()
        return True

    def list_grants(self) -> Dict[str, dict]:
        self._reload_if_changed()
        return dict(self._grants)
