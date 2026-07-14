#!/usr/bin/env python3
"""Synthetic dry-run of the FULL multimodal flow — the pilot rehearsal.

Self-contained: builds a throwaway vault in a temp directory, boots its own
gate on a free port, and walks the entire v1 surface end-to-end exactly as
a pilot would — on synthetic data only:

  records ingest → media ingest (all five classes) → onboarding-kit verify
  → record queries → media queries → attest → offline membership proof
  → grant + watermarked previews → both revocations (timed)
  → audit chain verify → no-plaintext-on-disk scan

Touches nothing outside its temp directory. Exit 0 = every stage passed.

Usage:  .venv/bin/python scripts/dry_run_multimodal.py [--keep]
"""
import argparse
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from app.blobvault import BlobVault                    # noqa: E402
from app.keyrelease import LocalMockKMS                # noqa: E402
from scripts.generate_synthetic_media import LEAK_MARKERS  # noqa: E402

PY = sys.executable


class StageFailure(Exception):
    pass


def http(url, body=None, key=None):
    headers = {"Content-Type": "application/json"}
    if key:
        headers["Authorization"] = "Bearer " + key
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, json.loads(r.read().decode())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode() or "{}")


def run(env, *argv):
    """Run an owner-side CLI; raise on nonzero; return stdout."""
    r = subprocess.run([PY, *argv], cwd=REPO, env=env,
                       capture_output=True, text=True, timeout=120)
    if r.returncode != 0:
        raise StageFailure(f"{Path(argv[0]).name} exited {r.returncode}: "
                           f"{r.stdout}{r.stderr}")
    return r.stdout


def expect(cond, why):
    if not cond:
        raise StageFailure(why)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--keep", action="store_true",
                        help="keep the temp directory for inspection")
    args = parser.parse_args()

    root = Path(tempfile.mkdtemp(prefix="ava-dryrun-"))
    data_dir, keys_dir, src = root / "data", root / "keys", root / "media_src"
    env = {**os.environ, "AVA_MODE": "local",
           "AVA_DATA_DIR": str(data_dir), "AVA_KEYS_DIR": str(keys_dir)}

    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    gate = f"http://127.0.0.1:{port}"

    stages_done, total, server = 0, 12, None
    print(f"MULTIMODAL DRY-RUN — synthetic data only — sandbox {root}")

    def stage(msg):
        nonlocal stages_done
        stages_done += 1
        print(f"  [{stages_done:2d}/{total}] PASS  {msg}")

    try:
        # 1 · records
        out = run(env, "scripts/generate_synthetic.py", "--n", "200")
        expect("ingested 200 synthetic records" in out, out)
        stage("200 synthetic records ingested, encrypted")

        # 2 · media, all five classes
        run(env, "scripts/generate_synthetic_media.py", "--dir", str(src))
        out = run(env, "scripts/ingest_media.py", "--path", str(src),
                  "--zone", "drill-zone-01", "--category", "drill")
        expect("ingested 6 object(s)" in out and "gis=1" in out
               and "unstructured=2" in out, out)
        stage("6 media objects across all five classes ingested, encrypted")

        # 3 · gate up
        server = subprocess.Popen(
            [PY, "-m", "uvicorn", "app.main:create_app", "--factory",
             "--host", "127.0.0.1", "--port", str(port)],
            cwd=REPO, env=env,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        deadline = time.time() + 15
        while True:
            try:
                urllib.request.urlopen(gate + "/healthz", timeout=1)
                break
            except Exception:
                expect(time.time() < deadline and server.poll() is None,
                       "gate failed to start")
                time.sleep(0.2)
        stage(f"gate live on :{port} (local mode)")

        # 4 · onboard a consumer, kit-verify before trusting
        out = run(env, "scripts/issue_consumer_key.py",
                  "--id", "dryrun-consumer", "--label", "dry run")
        key = next(t for t in out.split() if t.startswith("ava_"))
        out = run(env, "kit/ava_verify.py", "--gate", gate, "--key", key,
                  "--audit-pub", str(keys_dir / "audit_signing.pub"))
        expect("RESULT: VERIFIED" in out, out)
        stage("consumer onboarded; kit verification VERIFIED")

        # 5 · record queries
        st, body = http(gate + "/query", {"type": "count"}, key)
        expect(st == 200 and body["answer"]["result"] == 200, str(body))
        st, body = http(gate + "/query", {"type": "mean", "category": "alpha"}, key)
        expect(st == 200 and body["answer"]["matched"] > 0, str(body))
        stage("record queries answer (count exact, mean sane)")

        # 6 · media queries per class
        for mt, want in [("video", 1), ("audio", 1), ("tabular", 1),
                         ("unstructured", 2), ("gis", 1)]:
            st, body = http(gate + "/query",
                            {"target": "media", "type": "count", "media_type": mt}, key)
            expect(st == 200 and body["answer"]["result"] == want,
                   f"{mt}: {body}")
        stage("media counts exact for every class")

        # 7 · attest is trusted-only: refused by default, granted by owner
        st, body = http(gate + "/query",
                        {"target": "media", "type": "attest", "media_type": "gis"}, key)
        expect(st == 403 and "trusted" in body.get("detail", ""),
               f"untrusted attest must 403, got {st}: {body}")
        run(env, "scripts/set_trusted.py", "--id", "dryrun-consumer")
        st, body = http(gate + "/query",
                        {"target": "media", "type": "attest", "media_type": "gis"}, key)
        root_hex = body["answer"]["result"]
        expect(st == 200 and body["answer"]["matched"] == 1
               and len(root_hex) == 64, str(body))
        stage("attest: 403 untrusted → owner grants trust → Merkle root")

        # 8 · membership proof, verified offline against that root
        vault = BlobVault(data_dir / "vault", LocalMockKMS(keys_dir))
        gis_id = next(e["object_id"] for e in vault.iter_index()
                      if e["media_type"] == "gis")
        proof = run(env, "scripts/prove_membership.py",
                    "--object-id", gis_id, "--media-type", "gis")
        proof_path = root / "proof.json"
        proof_path.write_text(proof)
        out = run(env, "scripts/verify_membership.py",
                  "--proof", str(proof_path), "--root", root_hex)
        expect("VERIFIED" in out, out)
        stage("membership proof verifies OFFLINE against the attested root")

        # 9 · grant + watermarked previews (no identifiers in response)
        out = run(env, "scripts/issue_grant.py", "--consumer-id", "dryrun-consumer",
                  "--hours", "1", "--media-type", "unstructured",
                  "--zone", "drill-zone-01")
        grant_id = out.splitlines()[0].split()[-1]
        st, body = http(gate + "/preview", {"grant_id": grant_id, "limit": 5}, key)
        kinds = sorted(p["kind"] for p in body["previews"])
        expect(st == 200 and body["matched_total"] == 2
               and kinds == ["card", "thumbnail"], str(body)[:300])
        expect(gis_id not in str(body) and "object_id" not in str(body),
               "identifier leaked into preview response")
        stage("grant serves exactly 2 previews (thumbnail + card), zero identifiers")

        # 10 · both revocations, timed
        run(env, "scripts/revoke_grant.py", "--grant-id", grant_id)
        t0 = time.perf_counter()
        st, body = http(gate + "/preview", {"grant_id": grant_id}, key)
        t_grant = time.perf_counter() - t0
        expect(st == 403 and "revoked" in body["detail"], str(body))
        st, _ = http(gate + "/query", {"type": "count"}, key)
        expect(st == 200, "grant revocation must not kill queries")
        run(env, "scripts/revoke_consumer.py", "--id", "dryrun-consumer")
        t0 = time.perf_counter()
        st, body = http(gate + "/query", {"type": "count"}, key)
        t_consumer = time.perf_counter() - t0
        expect(st == 403 and "revoked" in body["detail"], str(body))
        stage(f"revocations bite in one request "
              f"(grant {t_grant:.3f}s, consumer {t_consumer:.3f}s)")

        # 11 · audit chain
        out = run(env, "scripts/verify_audit.py")
        expect("VERIFIED" in out, out)
        stage("audit chain verified — every entry intact and signed")

        # 12 · no plaintext on disk
        hits = [p.name for p in (data_dir / "vault").rglob("*") if p.is_file()
                and any(m.encode() in p.read_bytes() for m in LEAK_MARKERS)]
        expect(not hits, f"LEAK MARKERS FOUND ON DISK: {hits}")
        stage("no-plaintext scan clean (leak markers absent from vault files)")

        print(f"\nALL STAGES PASS ({stages_done}/{total}) — "
              "full multimodal flow rehearsed on synthetic data.")
        rc = 0
    except StageFailure as exc:
        print(f"  [{stages_done + 1:2d}/{total}] FAIL  {exc}")
        print(f"\nDRY-RUN FAILED at stage {stages_done + 1}/{total}.")
        rc = 1
    finally:
        if server is not None:
            server.terminate()
            server.wait(timeout=10)
        if args.keep:
            print(f"sandbox kept at {root}")
        else:
            shutil.rmtree(root, ignore_errors=True)
    sys.exit(rc)


if __name__ == "__main__":
    main()
