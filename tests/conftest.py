import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.config import Settings                 # noqa: E402
from app.keyrelease import LocalMockKMS         # noqa: E402
from app.main import create_app                 # noqa: E402
from app.vault import Vault                     # noqa: E402

# a small, fully known dataset so tests can assert exact answers
KNOWN_RECORDS = [
    {"id": "rec-0001", "ts": "2026-01-10T00:00:00+00:00", "category": "alpha", "zone": "zone-01", "value": 10.0, "quality": "good"},
    {"id": "rec-0002", "ts": "2026-02-10T00:00:00+00:00", "category": "alpha", "zone": "zone-02", "value": 20.0, "quality": "ok"},
    {"id": "rec-0003", "ts": "2026-03-10T00:00:00+00:00", "category": "beta",  "zone": "zone-01", "value": 30.0, "quality": "excellent"},
    {"id": "rec-0004", "ts": "2026-04-10T00:00:00+00:00", "category": "beta",  "zone": "zone-02", "value": 40.0, "quality": "good"},
    {"id": "rec-0005", "ts": "2026-05-10T00:00:00+00:00", "category": "gamma", "zone": "zone-01", "value": 50.0, "quality": "ok"},
]

# plaintext that must never hit disk. Markers must be IMPOSSIBLE in base64
# output, not just unlikely: short alphanumerics ("r1") occur in ciphertext
# by chance (~37%/run at this volume — a coin-flip test). Hyphens are not in
# the base64 alphabet, and 5+ char words are ~1e-9.
SECRET_MARKERS = ["alpha", "beta", "gamma", "zone-01", "rec-0001", "quality"]


@pytest.fixture()
def settings(tmp_path):
    s = Settings(mode="local", data_dir=tmp_path / "data", keys_dir=tmp_path / "keys")
    s.ensure_dirs()
    return s


@pytest.fixture()
def loaded_vault(settings):
    vault = Vault(settings.vault_dir, LocalMockKMS(settings.keys_dir))
    vault.ingest(KNOWN_RECORDS)
    return vault


@pytest.fixture()
def gate(settings, loaded_vault):
    """A TestClient over a gate whose vault already holds KNOWN_RECORDS,
    plus one issued consumer key."""
    app = create_app(settings)
    client = TestClient(app)
    key = app.state.registry.issue("consumer-test", "test consumer")
    return client, key, app
