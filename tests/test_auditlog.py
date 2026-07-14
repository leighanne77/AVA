"""The audit log: every query logged, chain verifiable, tampering detected."""
import json

from app.auditlog import verify_chain


def _pub(settings) -> bytes:
    return (settings.keys_dir / "audit_signing.pub").read_bytes()


def test_every_query_is_logged(gate, settings):
    client, key, _ = gate
    for i in range(3):
        client.post("/query", json={"type": "count"},
                    headers={"Authorization": f"Bearer {key}"})
    lines = settings.audit_path.read_text().strip().splitlines()
    assert len(lines) == 3
    entries = [json.loads(l) for l in lines]
    assert [e["seq"] for e in entries] == [1, 2, 3]
    assert all(e["consumer_id"] == "consumer-test" for e in entries)


def test_chain_verifies(gate, settings):
    client, key, _ = gate
    for _ in range(5):
        client.post("/query", json={"type": "count"},
                    headers={"Authorization": f"Bearer {key}"})
    ok, bad = verify_chain(settings.audit_path, _pub(settings))
    assert ok and bad is None


def test_tampering_detected(gate, settings):
    client, key, _ = gate
    for _ in range(5):
        client.post("/query", json={"type": "count"},
                    headers={"Authorization": f"Bearer {key}"})
    lines = settings.audit_path.read_text().strip().splitlines()
    entry = json.loads(lines[2])
    entry["consumer_id"] = "someone-else"        # rewrite history
    lines[2] = json.dumps(entry, sort_keys=True, separators=(",", ":"))
    settings.audit_path.write_text("\n".join(lines) + "\n")

    ok, bad = verify_chain(settings.audit_path, _pub(settings))
    assert not ok and bad == 3


def test_deleted_line_detected(gate, settings):
    client, key, _ = gate
    for _ in range(4):
        client.post("/query", json={"type": "count"},
                    headers={"Authorization": f"Bearer {key}"})
    lines = settings.audit_path.read_text().strip().splitlines()
    del lines[1]                                  # silently drop an entry
    settings.audit_path.write_text("\n".join(lines) + "\n")

    ok, bad = verify_chain(settings.audit_path, _pub(settings))
    assert not ok
