"""Attest queries: deterministic commitments, offline-verifiable membership."""
import pytest

from app.blobvault import BlobVault
from app.keyrelease import LocalMockKMS
from app.merkle import merkle_proof, merkle_root_hex, verify_membership

from test_blobvault import FIXTURES


@pytest.fixture()
def attest_gate(settings, gate):
    client, key, app = gate
    # attest is trusted-only (this layer); this fixture's consumer is
    # explicitly granted the privilege — the policy itself is tested in
    # test_attest_policy.py
    app.state.registry.set_trusted("consumer-test", True)
    vault = BlobVault(settings.vault_dir, LocalMockKMS(settings.keys_dir))
    entries = []
    for mt, (ext, payload) in FIXTURES.items():
        entries.append(vault.put(payload, ext, zone="zone-01", category="alpha",
                                 captured_at="2026-06-15T00:00:00+00:00"))
    return client, key, vault, entries


def _q(client, key, body):
    return client.post("/query", json=body, headers={"Authorization": f"Bearer {key}"})


# ---- merkle primitives ----

def test_root_is_order_independent():
    hashes = ["aa" * 32, "bb" * 32, "cc" * 32]
    assert merkle_root_hex(hashes) == merkle_root_hex(list(reversed(hashes)))


def test_root_changes_when_set_changes():
    base = ["aa" * 32, "bb" * 32]
    assert merkle_root_hex(base) != merkle_root_hex(base + ["cc" * 32])


def test_root_never_equals_a_leaf_hash():
    single = ["ab" * 32]
    assert merkle_root_hex(single) != single[0]  # domain separation


def test_proof_verifies_for_every_member_even_odd_sets():
    for n in (1, 2, 3, 4, 5, 8):  # even and odd tree shapes
        hashes = [format(i, "02x") * 32 for i in range(1, n + 1)]
        root = merkle_root_hex(hashes)
        for h in hashes:
            assert verify_membership(h, merkle_proof(hashes, h), root)


def test_proof_fails_for_non_member_and_tampered_proof():
    hashes = ["aa" * 32, "bb" * 32, "cc" * 32]
    root = merkle_root_hex(hashes)
    with pytest.raises(ValueError):
        merkle_proof(hashes, "dd" * 32)
    proof = merkle_proof(hashes, "aa" * 32)
    assert not verify_membership("dd" * 32, proof, root)
    if proof:
        bad = [dict(s, side=("L" if s["side"] == "R" else "R")) for s in proof]
        assert not verify_membership("aa" * 32, bad, root)


# ---- through the gate ----

def test_attest_is_deterministic(attest_gate):
    client, key, _, _ = attest_gate
    body = {"target": "media", "type": "attest", "media_type": "gis"}
    r1, r2 = _q(client, key, body).json(), _q(client, key, body).json()
    assert r1["answer"]["result"] == r2["answer"]["result"]
    assert r1["answer"]["matched"] == 1


def test_attest_root_changes_on_ingest(attest_gate):
    client, key, vault, _ = attest_gate
    body = {"target": "media", "type": "attest", "media_type": "gis"}
    before = _q(client, key, body).json()["answer"]
    vault.put(b"new-gis-object", ".geojson", zone="zone-01", category="alpha",
              captured_at="2026-06-20T00:00:00+00:00")
    after = _q(client, key, body).json()["answer"]
    assert before["result"] != after["result"]
    assert after["matched"] == 2


def test_attest_empty_set(attest_gate):
    client, key, _, _ = attest_gate
    r = _q(client, key, {"target": "media", "type": "attest", "zone": "zone-99"}).json()
    assert r["answer"] == {"type": "attest", "result": None, "matched": 0}


def test_attest_not_allowed_on_records(attest_gate):
    client, key, _, _ = attest_gate
    assert _q(client, key, {"target": "records", "type": "attest"}).status_code == 400


def test_attest_leaks_no_individual_hashes(attest_gate):
    client, key, _, entries = attest_gate
    r = _q(client, key, {"target": "media", "type": "attest"}).json()
    flat = str(r)
    for e in entries:
        assert e["sha256_plain"] not in flat
        assert e["object_id"] not in flat


def test_end_to_end_membership_proof(attest_gate):
    """Consumer attests → owner proves one object → consumer verifies offline."""
    client, key, vault, entries = attest_gate
    root = _q(client, key, {"target": "media", "type": "attest"}).json()["answer"]["result"]

    # owner side: build proof for the gis object against the same (empty) filters
    hashes = [e["sha256_plain"] for e in vault.iter_index()]
    gis = next(e for e in entries if e["media_type"] == "gis")
    proof = merkle_proof(hashes, gis["sha256_plain"])

    # consumer side: verify with root + proof only
    assert merkle_root_hex(hashes) == root
    assert verify_membership(gis["sha256_plain"], proof, root)
