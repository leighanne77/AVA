"""drills: synthetic media generator, revocation drill,
full-flow multimodal dry-run. The drills are the deliverable, so they are
tested the way they'll be used: as subprocesses, against real servers.
"""
import json
import os
import socket
import subprocess
import sys
import time
import urllib.request
from collections import Counter
from pathlib import Path

import pytest

from app.blobvault import BlobVault
from app.keyrelease import LocalMockKMS
from scripts.generate_synthetic_media import LEAK_MARKERS, make_files

REPO = Path(__file__).resolve().parent.parent


def test_generator_covers_all_five_classes(tmp_path):
    src = tmp_path / "src"
    make_files(src, seed=7)
    vault = BlobVault(tmp_path / "vault", LocalMockKMS(tmp_path / "keys"))
    for f in sorted(src.iterdir()):
        vault.put(f.read_bytes(), f.suffix, zone="z", category="c",
                  quality="ok", captured_at=None)
    counts = Counter(e["media_type"] for e in vault.iter_index())
    assert counts == {"video": 1, "audio": 1, "tabular": 1,
                      "unstructured": 2, "gis": 1}


def test_generator_markers_are_base64_impossible():
    """House rule: leak markers must be impossible in base64 output."""
    for m in LEAK_MARKERS:
        assert "-" in m and len(m) >= 5


@pytest.fixture()
def drill_gate(tmp_path):
    """A real uvicorn gate over empty tmp state, plus the env the
    owner-side drill scripts need to share its registries."""
    data_dir, keys_dir = tmp_path / "data", tmp_path / "keys"
    env = {**os.environ, "AVA_MODE": "local",
           "AVA_DATA_DIR": str(data_dir), "AVA_KEYS_DIR": str(keys_dir)}
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    base = f"http://127.0.0.1:{port}"
    proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "app.main:create_app",
         "--factory", "--host", "127.0.0.1", "--port", str(port)],
        cwd=REPO, env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        deadline = time.time() + 15
        while True:
            try:
                urllib.request.urlopen(base + "/healthz", timeout=1)
                break
            except Exception:
                if time.time() > deadline or proc.poll() is not None:
                    raise RuntimeError("gate failed to start")
                time.sleep(0.2)
        yield base, env, data_dir
    finally:
        proc.terminate()
        proc.wait(timeout=10)


def test_revocation_drill_passes_and_logs(drill_gate):
    base, env, data_dir = drill_gate
    r = subprocess.run(
        [sys.executable, str(REPO / "scripts/drill_revocation.py"),
         "--gate", base],
        cwd=REPO, env=env, capture_output=True, text=True, timeout=120)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "DRILL PASS" in r.stdout
    assert "SURVIVE grant revocation" in r.stdout   # grant kill ≠ key kill
    entries = [json.loads(line) for line in
               (data_dir / "drills.jsonl").read_text().splitlines()]
    assert len(entries) == 1 and entries[0]["result"] == "PASS"
    assert 0 < entries[0]["grant_revoke_seconds"] < 60
    assert 0 < entries[0]["consumer_revoke_seconds"] < 60


def test_revocation_drill_fails_cleanly_when_gate_down(tmp_path):
    env = {**os.environ, "AVA_MODE": "local",
           "AVA_DATA_DIR": str(tmp_path / "data"),
           "AVA_KEYS_DIR": str(tmp_path / "keys")}
    r = subprocess.run(
        [sys.executable, str(REPO / "scripts/drill_revocation.py"),
         "--gate", "http://127.0.0.1:9", "--max-seconds", "1"],
        cwd=REPO, env=env, capture_output=True, text=True, timeout=120)
    assert r.returncode == 1
    assert "DRILL FAIL" in r.stdout
    assert "Traceback" not in r.stderr


def test_dry_run_multimodal_all_green():
    r = subprocess.run(
        [sys.executable, str(REPO / "scripts/dry_run_multimodal.py")],
        cwd=REPO, env={**os.environ}, capture_output=True, text=True,
        timeout=300)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "ALL STAGES PASS (12/12)" in r.stdout
