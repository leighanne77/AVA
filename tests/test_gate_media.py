"""Media queries through the gate: answers over the index, never the objects."""
import pytest

from app.blobvault import BlobVault
from app.keyrelease import LocalMockKMS

from test_blobvault import FIXTURES

ALLOWED_RESPONSE_KEYS = {"answer", "query_id", "computed_at", "audit_entry_hash", "gate_version"}
ALLOWED_ANSWER_KEYS = {"type", "result", "matched"}


@pytest.fixture()
def media_gate(settings, gate):
    """The standard gate, with a known media population ingested BEFORE
    create_app... actually after — same dirs, same DEK, index re-read per query."""
    client, key, app = gate
    vault = BlobVault(settings.vault_dir, LocalMockKMS(settings.keys_dir))
    ingested = []
    # all five classes in zone-01, captured June 2026
    for mt, (ext, payload) in FIXTURES.items():
        ingested.append(vault.put(payload, ext, zone="zone-01", category="alpha",
                                  captured_at="2026-06-15T00:00:00+00:00"))
    # two extra gis objects: another zone, and one with unknown capture time
    ingested.append(vault.put(b"gis-two", ".geojson", zone="zone-02", category="beta",
                              captured_at="2026-03-01T00:00:00+00:00"))
    ingested.append(vault.put(b"gis-three", ".geojson", zone="zone-02", category="beta",
                              captured_at=None))
    return client, key, ingested


def _q(client, key, body):
    return client.post("/query", json=body, headers={"Authorization": f"Bearer {key}"})


def test_count_by_media_type(media_gate):
    client, key, _ = media_gate
    r = _q(client, key, {"target": "media", "type": "count", "media_type": "gis"})
    assert r.status_code == 200
    assert r.json()["answer"]["result"] == 3


def test_count_all_media(media_gate):
    client, key, _ = media_gate
    assert _q(client, key, {"target": "media", "type": "count"}).json()["answer"]["result"] == 7


def test_zone_and_time_filters(media_gate):
    client, key, _ = media_gate
    assert _q(client, key, {"target": "media", "type": "count",
                            "zone": "zone-02"}).json()["answer"]["result"] == 2
    # time-bounded: the unknown-captured_at object must NOT match
    r = _q(client, key, {"target": "media", "type": "count", "media_type": "gis",
                         "ts_from": "2026-01-01", "ts_to": "2026-12-31"})
    assert r.json()["answer"]["result"] == 2


def test_exists_and_size_aggregates(media_gate):
    client, key, _ = media_gate
    assert _q(client, key, {"target": "media", "type": "exists",
                            "media_type": "video"}).json()["answer"]["result"] is True
    total = _q(client, key, {"target": "media", "type": "sum",
                             "media_type": "gis"}).json()["answer"]
    assert total["result"] > 0 and total["matched"] == 3


def test_media_type_invalid_or_misplaced(media_gate):
    client, key, _ = media_gate
    assert _q(client, key, {"target": "media", "type": "count",
                            "media_type": "hologram"}).status_code == 400
    assert _q(client, key, {"target": "records", "type": "count",
                            "media_type": "gis"}).status_code == 400
    assert _q(client, key, {"target": "everything", "type": "count"}).status_code == 400


def test_records_queries_unaffected(media_gate):
    client, key, _ = media_gate
    # conftest KNOWN_RECORDS still answer exactly as before
    assert _q(client, key, {"type": "count"}).json()["answer"]["result"] == 5


def test_media_answers_leak_nothing(media_gate):
    """Extended tripwire: no object_id, hash, extension, or mime ever leaves."""
    client, key, ingested = media_gate
    responses = [
        _q(client, key, {"target": "media", "type": "count"}).json(),
        _q(client, key, {"target": "media", "type": "sum", "media_type": "gis"}).json(),
        _q(client, key, {"target": "media", "type": "exists", "media_type": "audio"}).json(),
    ]
    for payload in responses:
        assert set(payload.keys()) <= ALLOWED_RESPONSE_KEYS
        assert set(payload["answer"].keys()) <= ALLOWED_ANSWER_KEYS
        flat = str(payload)
        for entry in ingested:
            assert entry["object_id"] not in flat
            assert entry["sha256_plain"] not in flat
        for needle in (".geojson", ".mp4", "image/", "application/"):
            assert needle not in flat


def test_no_blob_egress_endpoint_exists(media_gate):
    """There must be no route that could serve an object."""
    client, key, ingested = media_gate
    oid = ingested[0]["object_id"]
    for path in (f"/media/{oid}", f"/objects/{oid}", f"/blob/{oid}", "/media"):
        r = client.get(path, headers={"Authorization": f"Bearer {key}"})
        assert r.status_code == 404
