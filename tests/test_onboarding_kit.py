"""consumer onboarding kit.

Two layers: the gate's /attestation now serves the audit public key
(identity cross-check surface), and kit/ava_verify.py — the standalone,
stdlib-only script a consumer runs before trusting the gate. The kit is
exercised for real: a subprocess uvicorn server, the script run as a
consumer would run it, against both a healthy gate and sabotaged inputs.
"""
import os
import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.auditlog import public_key_fingerprint
from app.consumers import ConsumerRegistry
from app.keyrelease import LocalMockKMS
from app.vault import Vault
from kit.ava_verify import pem_fingerprint

from conftest import KNOWN_RECORDS

REPO = Path(__file__).resolve().parent.parent
KIT = REPO / "kit" / "ava_verify.py"

ATTESTATION_KEYS = {"mode", "attestation", "key_release",
                    "audit_pub_pem", "audit_pub_sha256", "note"}


# ---------- /attestation surface (TestClient) ----------

def test_attestation_serves_matching_audit_pub(gate):
    client, _, app = gate
    body = client.get("/attestation").json()
    on_disk = (app.state.settings.keys_dir / "audit_signing.pub").read_text()
    assert body["audit_pub_pem"] == on_disk
    assert body["audit_pub_sha256"] == public_key_fingerprint(on_disk.encode())


def test_attestation_surface_is_closed_and_public_only(gate):
    """Tripwire: /attestation is unauthenticated — it must carry identity
    material only. No private key bytes, no extra fields, ever."""
    client, _, _ = gate
    body = client.get("/attestation").json()
    assert set(body.keys()) == ATTESTATION_KEYS
    assert "PRIVATE" not in str(body)          # PEM private armor marker
    assert "PUBLIC KEY" in body["audit_pub_pem"]


def test_kit_fingerprint_matches_der_hash(gate):
    """The kit's stdlib PEM parse must agree with `cryptography`'s DER."""
    import hashlib
    _, _, app = gate
    pem = (app.state.settings.keys_dir / "audit_signing.pub").read_bytes()
    pub = serialization.load_pem_public_key(pem)
    der = pub.public_bytes(serialization.Encoding.DER,
                           serialization.PublicFormat.SubjectPublicKeyInfo)
    assert pem_fingerprint(pem.decode()) == hashlib.sha256(der).hexdigest()
    assert pem_fingerprint(pem.decode()) == public_key_fingerprint(pem)


# ---------- the kit script against a real server ----------

@pytest.fixture(scope="module")
def live_gate(tmp_path_factory):
    """A real uvicorn gate in a subprocess, vault pre-loaded, one active
    and one revoked consumer key. Yields (base_url, keys, keys_dir)."""
    root = tmp_path_factory.mktemp("kitgate")
    data_dir, keys_dir = root / "data", root / "keys"
    data_dir.mkdir(), keys_dir.mkdir()

    Vault(data_dir / "vault", LocalMockKMS(keys_dir)).ingest(KNOWN_RECORDS)
    registry = ConsumerRegistry(data_dir / "consumers.json")
    good_key = registry.issue("consumer-kit", "kit test")
    revoked_key = registry.issue("consumer-gone", "kit test, revoked")
    registry.revoke("consumer-gone")

    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    base = f"http://127.0.0.1:{port}"

    proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "app.main:create_app",
         "--factory", "--host", "127.0.0.1", "--port", str(port)],
        cwd=REPO, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        env={**os.environ, "AVA_MODE": "local",
             "AVA_DATA_DIR": str(data_dir), "AVA_KEYS_DIR": str(keys_dir)},
    )
    try:
        deadline = time.time() + 15
        while True:
            try:
                urllib.request.urlopen(base + "/healthz", timeout=1)
                break
            except Exception:
                if time.time() > deadline or proc.poll() is not None:
                    raise RuntimeError("gate subprocess failed to start")
                time.sleep(0.2)
        yield base, {"good": good_key, "revoked": revoked_key}, keys_dir
    finally:
        proc.terminate()
        proc.wait(timeout=10)


def _run_kit(base, key, pub_path):
    return subprocess.run(
        [sys.executable, str(KIT), "--gate", base, "--key", key,
         "--audit-pub", str(pub_path)],
        capture_output=True, text=True, timeout=60)


def test_kit_verifies_healthy_gate(live_gate):
    base, keys, keys_dir = live_gate
    r = _run_kit(base, keys["good"], keys_dir / "audit_signing.pub")
    assert r.returncode == 0, r.stdout + r.stderr
    assert "RESULT: VERIFIED" in r.stdout
    assert "LOCAL DEV MODE" in r.stdout      # dev mode must warn, loudly
    assert "audit_entry_hash" in r.stdout    # the receipt is shown


def test_kit_fails_on_wrong_audit_key(live_gate, tmp_path):
    """Named identity tripwire: a gate holding a different audit key than
    the owner published must FAIL verification, not warn."""
    base, keys, _ = live_gate
    impostor = tmp_path / "other.pub"
    impostor.write_bytes(
        Ed25519PrivateKey.generate().public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo))
    r = _run_kit(base, keys["good"], impostor)
    assert r.returncode == 1
    assert "AUDIT KEY MISMATCH" in r.stdout
    assert "RESULT: FAILED" in r.stdout


def test_kit_fails_on_unknown_key(live_gate):
    base, _, keys_dir = live_gate
    r = _run_kit(base, "ava_not_a_real_key", keys_dir / "audit_signing.pub")
    assert r.returncode == 1
    assert "key rejected (401)" in r.stdout


def test_kit_fails_on_revoked_key(live_gate):
    base, keys, keys_dir = live_gate
    r = _run_kit(base, keys["revoked"], keys_dir / "audit_signing.pub")
    assert r.returncode == 1
    assert "REVOKED (403)" in r.stdout


def test_kit_fails_on_unreachable_gate(tmp_path, live_gate):
    _, keys, keys_dir = live_gate
    r = _run_kit("http://127.0.0.1:9", keys["good"],
                 keys_dir / "audit_signing.pub")
    assert r.returncode == 1
    assert "unreachable" in r.stdout


def test_kit_is_stdlib_only():
    """The kit must run on a consumer's bare python3 — if an import of a
    third-party package sneaks in, this trips."""
    src = KIT.read_text()
    banned = ["cryptography", "fastapi", "requests", "httpx", "pydantic",
              "from app", "import app"]
    assert not [b for b in banned if b in src]
