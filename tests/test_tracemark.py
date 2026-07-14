"""the keyed invisible tracing mark.

Named invariants: benign transforms never break tracing; stripping the
visible mark leaves the invisible one; without the right key or pair,
detection stays below threshold (keyed blindness); the mark stays within
its amplitude budget (invisible); the live /preview pipeline carries it.
"""
import base64
import io
import subprocess
import sys
from pathlib import Path

import pytest
from PIL import Image, ImageEnhance

from app import tracemark
from app.grants import GrantRegistry
from scripts.generate_synthetic_media import make_files

REPO = Path(__file__).resolve().parent.parent
KEY = bytes(range(32))
PAIR = ("consumer-leak", "grant-1234")


def _photo(tmp_path, seed=1):
    src = tmp_path / f"src{seed}"
    make_files(src, seed=seed)
    img = Image.open(src / "photo.png").convert("RGB")
    img.thumbnail((256, 256))
    return img


def _jpeg(im, q=35):
    b = io.BytesIO()
    im.save(b, "JPEG", quality=q)
    return Image.open(io.BytesIO(b.getvalue())).convert("RGB")


@pytest.fixture()
def marked(tmp_path):
    """A marked preview as actually served: embed, then JPEG q35."""
    return _jpeg(tracemark.embed(_photo(tmp_path), KEY, *PAIR))


def test_detects_the_embedded_pair(marked):
    hit, z = tracemark.detect(marked, KEY, *PAIR)
    assert hit and z >= tracemark.Z_THRESHOLD


def test_keyed_blindness_wrong_pair_and_wrong_key(marked):
    hit, z = tracemark.detect(marked, KEY, "consumer-innocent", "grant-1234")
    assert not hit and z < tracemark.Z_THRESHOLD
    hit, z = tracemark.detect(marked, bytes(32), *PAIR)
    assert not hit and z < tracemark.Z_THRESHOLD


def test_unmarked_image_detects_nothing(tmp_path):
    hit, z = tracemark.detect(_jpeg(_photo(tmp_path)), KEY, *PAIR)
    assert not hit and z < tracemark.Z_THRESHOLD


def test_benign_transforms_never_break_tracing(marked):
    """The green-forever tripwire: what an honest buyer's tools do must
    never defeat leak attribution."""
    w, h = marked.size
    for attacked in (
        _jpeg(marked, 30),
        marked.resize((w // 2, h // 2)),
        ImageEnhance.Brightness(marked).enhance(1.1),
    ):
        hit, z = tracemark.detect(attacked, KEY, *PAIR)
        assert hit, f"benign transform broke tracing (z={z:.2f})"


def test_amplitude_stays_in_budget(tmp_path):
    """Invisibility bound: mean luma delta ≈ STRENGTH; per-pixel never more
    than STRENGTH+3 (YCbCr↔RGB roundtrip rounding adds ≤2 levels)."""
    img = _photo(tmp_path)
    marked = tracemark.embed(img, KEY, *PAIR)
    a = list(img.convert("L").getdata())
    b = list(marked.convert("L").getdata())
    deltas = [abs(x - y) for x, y in zip(a, b)]
    assert sum(deltas) / len(deltas) <= tracemark.STRENGTH + 0.5
    assert max(deltas) <= tracemark.STRENGTH + 3


def test_preview_pipeline_carries_the_mark(gate, tmp_path):
    """End-to-end through the real gate: grant → /preview → decode the
    served thumbnail → attribute the leak to the right (consumer, grant)."""
    client, key, app = gate
    src = tmp_path / "media"
    make_files(src, seed=9)
    app.state.blobvault.put((src / "photo.png").read_bytes(), ".png",
                            zone="zone-07", category="alpha", quality="ok",
                            captured_at="2026-06-01T00:00:00+00:00")
    grant_id = app.state.grants.issue("consumer-test", {"zone": "zone-07"},
                                      ttl_hours=1)
    r = client.post("/preview", json={"grant_id": grant_id},
                    headers={"Authorization": f"Bearer {key}"})
    assert r.status_code == 200
    thumb, = [p for p in r.json()["previews"] if p["kind"] == "thumbnail"]
    leaked = Image.open(io.BytesIO(base64.b64decode(thumb["data_b64"])))

    trace_key = tracemark.load_or_create_key(app.state.settings.keys_dir)
    hit, z = tracemark.detect(leaked, trace_key, "consumer-test", grant_id)
    assert hit, f"served preview not attributable (z={z:.2f})"
    hit, _ = tracemark.detect(leaked, trace_key, "consumer-other", grant_id)
    assert not hit


def test_detect_cli_names_the_leaker(tmp_path):
    """The owner tool, as it would really run: registry of several grants,
    a leaked file on disk, attribution out."""
    data_dir, keys_dir = tmp_path / "data", tmp_path / "keys"
    data_dir.mkdir()
    grants = GrantRegistry(data_dir / "grants.json")
    leak_grant = grants.issue("consumer-leak", {"zone": "z"}, ttl_hours=1)
    for i in range(4):
        grants.issue(f"consumer-{i}", {"zone": "z"}, ttl_hours=1)
    key = tracemark.load_or_create_key(keys_dir)

    make_files(tmp_path / "src", seed=2)
    img = Image.open(tmp_path / "src" / "photo.png").convert("RGB")
    img.thumbnail((256, 256))
    leaked = tmp_path / "leaked.jpg"
    tracemark.embed(img, key, "consumer-leak", leak_grant).save(
        leaked, "JPEG", quality=50)

    env = {"AVA_MODE": "local", "AVA_DATA_DIR": str(data_dir),
           "AVA_KEYS_DIR": str(keys_dir), "PATH": "/usr/bin:/bin"}
    r = subprocess.run(
        [sys.executable, str(REPO / "scripts/detect_watermark.py"),
         "--image", str(leaked)],
        cwd=REPO, env=env, capture_output=True, text=True, timeout=120)
    assert r.returncode == 0, r.stdout + r.stderr
    assert f"ATTRIBUTION: consumer 'consumer-leak' under grant {leak_grant}" \
        in r.stdout


def test_removal_drill_passes(tmp_path):
    env = {"AVA_MODE": "local", "AVA_DATA_DIR": str(tmp_path / "data"),
           "AVA_KEYS_DIR": str(tmp_path / "keys"), "PATH": "/usr/bin:/bin"}
    r = subprocess.run(
        [sys.executable, str(REPO / "scripts/drill_watermark_removal.py")],
        cwd=REPO, env=env, capture_output=True, text=True, timeout=300)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "DRILL PASS" in r.stdout
    assert "strip_visible_mark" in r.stdout
    assert (tmp_path / "data" / "drills.jsonl").exists()
