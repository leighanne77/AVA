"""Sample grants end-to-end: scoped, expiring, revocable, fully audited."""
import io
import json

import pytest
from PIL import Image

from app.blobvault import BlobVault
from app.keyrelease import LocalMockKMS

PREVIEW_RESPONSE_KEYS = {"previews", "matched_total", "query_id", "computed_at",
                         "audit_entry_hash", "gate_version"}
PREVIEW_KEYS = {"kind", "media_type", "zone", "category", "captured_at",
                "watermark", "mime", "data_b64", "card"}


def _png_bytes(color=(10, 120, 40)) -> bytes:
    buf = io.BytesIO()
    Image.new("RGB", (640, 480), color).save(buf, format="PNG")
    return buf.getvalue()


@pytest.fixture()
def granted(settings, gate):
    """Gate + media population + one active grant scoped to zone-01 unstructured."""
    client, key, app = gate
    vault = BlobVault(settings.vault_dir, LocalMockKMS(settings.keys_dir))
    entries = [
        vault.put(_png_bytes(), ".png", zone="zone-01", category="alpha",
                  captured_at="2026-06-01T00:00:00+00:00"),
        vault.put(_png_bytes((80, 10, 90)), ".png", zone="zone-01", category="alpha",
                  captured_at="2026-06-02T00:00:00+00:00"),
        vault.put(b"a,b\n1,2\n", ".csv", zone="zone-01", category="alpha",
                  captured_at="2026-06-03T00:00:00+00:00"),
        # out of scope: other zone
        vault.put(_png_bytes((5, 5, 5)), ".png", zone="zone-09", category="alpha",
                  captured_at="2026-06-04T00:00:00+00:00"),
    ]
    grant_id = app.state.grants.issue(
        "consumer-test", {"zone": "zone-01"}, ttl_hours=1)
    return client, key, app, grant_id, entries


def _p(client, key, body):
    return client.post("/preview", json=body, headers={"Authorization": f"Bearer {key}"})


def test_preview_serves_scoped_watermarked_previews(granted):
    client, key, app, grant_id, entries = granted
    r = _p(client, key, {"grant_id": grant_id, "limit": 5})
    assert r.status_code == 200
    payload = r.json()
    assert set(payload.keys()) <= PREVIEW_RESPONSE_KEYS
    assert payload["matched_total"] == 3          # zone-09 object out of scope
    kinds = [p["kind"] for p in payload["previews"]]
    assert kinds.count("thumbnail") == 2 and kinds.count("card") == 1
    for p in payload["previews"]:
        assert set(p.keys()) <= PREVIEW_KEYS
        assert p["watermark"]["consumer_id"] == "consumer-test"
        assert p["watermark"]["grant_id"] == grant_id
        assert p["zone"] == "zone-01"


def test_preview_requires_consumer_key(granted):
    client, _, _, grant_id, _ = granted
    assert client.post("/preview", json={"grant_id": grant_id}).status_code == 401


def test_unknown_grant_404(granted):
    client, key, _, _, _ = granted
    assert _p(client, key, {"grant_id": "00000000-0000-0000-0000-000000000000"}).status_code == 404


def test_someone_elses_grant_403(granted):
    client, key, app, _, _ = granted
    app.state.registry.issue("consumer-other", "other")
    other_grant = app.state.grants.issue("consumer-other", {}, ttl_hours=1)
    r = _p(client, key, {"grant_id": other_grant})
    assert r.status_code == 403 and "not_yours" in r.json()["detail"]


def test_expired_grant_403(granted):
    client, key, app, _, _ = granted
    stale = app.state.grants.issue("consumer-test", {}, ttl_hours=-1)  # born expired
    r = _p(client, key, {"grant_id": stale})
    assert r.status_code == 403 and "expired" in r.json()["detail"]


def test_revoked_grant_403_within_one_request(granted, settings):
    from app.grants import GrantRegistry
    client, key, app, grant_id, _ = granted
    assert _p(client, key, {"grant_id": grant_id}).status_code == 200
    # revoke from a SEPARATE registry instance — the CLI path
    GrantRegistry(settings.grants_path).revoke(grant_id)
    r = _p(client, key, {"grant_id": grant_id})
    assert r.status_code == 403 and "revoked" in r.json()["detail"]


def test_limit_is_clamped(granted):
    client, key, _, grant_id, _ = granted
    assert _p(client, key, {"grant_id": grant_id, "limit": 99}).status_code == 422
    r = _p(client, key, {"grant_id": grant_id, "limit": 1})
    assert len(r.json()["previews"]) == 1 and r.json()["matched_total"] == 3


def test_audit_records_exactly_what_was_served(granted, settings):
    client, key, _, grant_id, entries = granted
    _p(client, key, {"grant_id": grant_id, "limit": 2})
    last = json.loads(settings.audit_path.read_text().strip().splitlines()[-1])
    assert last["query"]["endpoint"] == "preview"
    assert last["query"]["grant_id"] == grant_id
    served = last["query"]["served_object_ids"]
    assert len(served) == 2
    in_scope_ids = {e["object_id"] for e in entries if e["zone"] == "zone-01"}
    assert set(served) <= in_scope_ids


def test_preview_response_leaks_no_identifiers(granted):
    client, key, _, grant_id, entries = granted
    flat = str(_p(client, key, {"grant_id": grant_id, "limit": 5}).json())
    for e in entries:
        assert e["object_id"] not in flat
        assert e["sha256_plain"] not in flat


def test_query_endpoint_unaffected_by_grants(granted):
    client, key, _, _, _ = granted
    r = client.post("/query", json={"target": "media", "type": "count"},
                    headers={"Authorization": f"Bearer {key}"})
    assert r.json()["answer"]["result"] == 4
