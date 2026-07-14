"""The gate: auth enforced, answers exact, answers-only, revocation immediate."""

ALLOWED_RESPONSE_KEYS = {"answer", "query_id", "computed_at", "audit_entry_hash", "gate_version"}
ALLOWED_ANSWER_KEYS = {"type", "result", "matched"}
RECORD_FIELD_NAMES = {"id", "ts", "category", "zone", "value", "quality"}


def _q(client, key, body):
    return client.post("/query", json=body, headers={"Authorization": f"Bearer {key}"})


def test_healthz_is_public(gate):
    client, _, _ = gate
    r = client.get("/healthz")
    assert r.status_code == 200
    assert r.json()["mode"] == "local"


def test_query_requires_key(gate):
    client, _, _ = gate
    assert client.post("/query", json={"type": "count"}).status_code == 401
    assert client.post("/query", json={"type": "count"},
                       headers={"Authorization": "Bearer ava_wrong"}).status_code == 401


def test_count_and_filters(gate):
    client, key, _ = gate
    assert _q(client, key, {"type": "count"}).json()["answer"]["result"] == 5
    assert _q(client, key, {"type": "count", "category": "alpha"}).json()["answer"]["result"] == 2
    assert _q(client, key, {"type": "count", "zone": "zone-01"}).json()["answer"]["result"] == 3
    assert _q(client, key, {"type": "count", "ts_from": "2026-03-01"}).json()["answer"]["result"] == 3


def test_aggregates(gate):
    client, key, _ = gate
    assert _q(client, key, {"type": "sum", "category": "beta"}).json()["answer"]["result"] == 70.0
    mean = _q(client, key, {"type": "mean", "zone": "zone-01"}).json()["answer"]
    assert mean["result"] == 30.0 and mean["matched"] == 3
    assert _q(client, key, {"type": "exists", "category": "gamma"}).json()["answer"]["result"] is True
    assert _q(client, key, {"type": "exists", "category": "omega"}).json()["answer"]["result"] is False
    empty_mean = _q(client, key, {"type": "mean", "category": "omega"}).json()["answer"]
    assert empty_mean["result"] is None and empty_mean["matched"] == 0


def test_bad_query_type_rejected(gate):
    client, key, _ = gate
    r = _q(client, key, {"type": "dump_all"})
    assert r.status_code == 400


def test_answers_only_no_record_leakage(gate):
    """The load-bearing test: no response may carry record content."""
    client, key, _ = gate
    for body in [{"type": "count"}, {"type": "sum"}, {"type": "mean"},
                 {"type": "exists", "category": "alpha"}]:
        payload = _q(client, key, body).json()
        assert set(payload.keys()) <= ALLOWED_RESPONSE_KEYS
        assert set(payload["answer"].keys()) <= ALLOWED_ANSWER_KEYS
        # no record field name or known record id may appear anywhere in the response
        flat = str(payload)
        for field in RECORD_FIELD_NAMES - {"type"}:
            assert f"'{field}'" not in flat.replace('"', "'") or field in ("category", "zone"), \
                f"record field '{field}' leaked into response"
        assert "rec-0001" not in flat and "excellent" not in flat


def test_revocation_is_immediate(gate):
    client, key, app = gate
    assert _q(client, key, {"type": "count"}).status_code == 200
    app.state.registry.revoke("consumer-test")
    r = _q(client, key, {"type": "count"})
    assert r.status_code == 403
    assert r.json()["detail"] == "key revoked"


def test_revocation_via_separate_registry_instance(gate, settings):
    """CLI revocation (a different process) must bite on the running gate."""
    from app.consumers import ConsumerRegistry
    client, key, _ = gate
    assert _q(client, key, {"type": "count"}).status_code == 200
    other = ConsumerRegistry(settings.registry_path)   # simulates the CLI process
    assert other.revoke("consumer-test") is True
    assert _q(client, key, {"type": "count"}).status_code == 403
