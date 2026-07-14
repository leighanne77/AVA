"""attest is trusted-only.

Commitments confirm dataset size/shape over time, so `attest` is an
owner-granted privilege: per-consumer flag, off by default, revocable
within one request. These are the named tripwires for that policy.
"""
import json
import subprocess
import sys
from pathlib import Path

from app.consumers import ConsumerRegistry

REPO = Path(__file__).resolve().parent.parent
ATTEST = {"target": "media", "type": "attest", "media_type": "gis"}


def _q(client, key, body):
    return client.post("/query", json=body, headers={"Authorization": f"Bearer {key}"})


def test_attest_refused_for_untrusted_consumer(gate):
    """The tripwire: a default (untrusted) consumer must never receive a
    commitment — 403, not an empty answer."""
    client, key, _ = gate
    r = _q(client, key, ATTEST)
    assert r.status_code == 403
    assert "trusted" in r.json()["detail"]


def test_untrusted_consumer_keeps_all_other_queries(gate):
    """Trust gates exactly one query type — answers stay available."""
    client, key, _ = gate
    assert _q(client, key, {"type": "count"}).status_code == 200
    assert _q(client, key, {"target": "media", "type": "count"}).status_code == 200
    assert _q(client, key, {"type": "exists", "category": "alpha"}).status_code == 200


def test_attest_allowed_once_trusted(gate):
    client, key, app = gate
    app.state.registry.set_trusted("consumer-test", True)
    r = _q(client, key, ATTEST)
    assert r.status_code == 200
    assert r.json()["answer"]["type"] == "attest"


def test_trust_revocation_bites_within_one_request(gate, settings):
    """Owner-side flip via a SEPARATE registry instance (as the CLI would
    do it) — the running gate must see it on the very next request."""
    client, key, app = gate
    app.state.registry.set_trusted("consumer-test", True)
    assert _q(client, key, ATTEST).status_code == 200
    ConsumerRegistry(settings.registry_path).set_trusted("consumer-test", False)
    assert _q(client, key, ATTEST).status_code == 403


def test_legacy_registry_entries_default_untrusted(settings, gate):
    """Consumers issued before the flag existed must NOT inherit the
    privilege: strip the field from disk and re-authenticate."""
    client, key, app = gate
    doc = json.loads(settings.registry_path.read_text())
    doc["consumers"]["consumer-test"].pop("trusted", None)
    settings.registry_path.write_text(json.dumps(doc))
    assert _q(client, key, ATTEST).status_code == 403


def test_cli_issue_trusted_and_flip(tmp_path):
    """The owner tools, as they really run: --trusted at issuance,
    set_trusted.py to grant/revoke afterward."""
    import os
    env = {**os.environ, "AVA_MODE": "local",
           "AVA_DATA_DIR": str(tmp_path / "data"),
           "AVA_KEYS_DIR": str(tmp_path / "keys")}

    r = subprocess.run([sys.executable, str(REPO / "scripts/issue_consumer_key.py"),
                        "--id", "c-trusted", "--trusted"],
                       cwd=REPO, env=env, capture_output=True, text=True)
    assert r.returncode == 0 and "TRUSTED" in r.stdout
    reg = json.loads((tmp_path / "data" / "consumers.json").read_text())
    assert reg["consumers"]["c-trusted"]["trusted"] is True

    r = subprocess.run([sys.executable, str(REPO / "scripts/set_trusted.py"),
                        "--id", "c-trusted", "--revoke"],
                       cwd=REPO, env=env, capture_output=True, text=True)
    assert r.returncode == 0 and "REVOKED" in r.stdout
    reg = json.loads((tmp_path / "data" / "consumers.json").read_text())
    assert reg["consumers"]["c-trusted"]["trusted"] is False

    r = subprocess.run([sys.executable, str(REPO / "scripts/set_trusted.py"),
                        "--id", "c-missing"],
                       cwd=REPO, env=env, capture_output=True, text=True)
    assert r.returncode == 1
