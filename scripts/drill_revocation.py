#!/usr/bin/env python3
"""The revocation drill — rehearse the switch, MEASURE it, log the number.

Run on the gate host (same AVA_DATA_DIR/AVA_KEYS_DIR the gate uses),
against the live gate. The drill:

  1. issues a throwaway consumer + grant (labelled 'drill', kept forever
     as audit evidence — nothing is deleted)
  2. proves both work (200s)
  3. revokes the GRANT   → times until previews die   (grant leash only)
  4. proves queries still work — grant kill ≠ key kill
  5. revokes the CONSUMER → times until everything dies
  6. appends the numbers to data/drills.jsonl and prints the report

Exit 0 = both revocations bit within --max-seconds (default 60; the v1
exit criterion says "minutes" — we hold ourselves to seconds).

Usage:  .venv/bin/python scripts/drill_revocation.py [--gate http://127.0.0.1:8080]
"""
import argparse
import json
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.config import Settings          # noqa: E402
from app.consumers import ConsumerRegistry  # noqa: E402
from app.grants import GrantRegistry     # noqa: E402


def _post(url: str, body: dict, key: str):
    req = urllib.request.Request(
        url, data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json",
                 "Authorization": "Bearer " + key})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, json.loads(r.read().decode())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode() or "{}")
    except (urllib.error.URLError, OSError) as exc:
        return None, {"detail": f"unreachable: {exc}"}


def _time_until_403(call, max_seconds: float, expect_detail: str):
    """Poll `call` until it returns 403 with the expected detail.
    Returns seconds elapsed since the poll started, or None on timeout."""
    t0 = time.perf_counter()
    while time.perf_counter() - t0 < max_seconds:
        status, body = call()
        if status == 403 and expect_detail in str(body.get("detail", "")):
            return time.perf_counter() - t0
        time.sleep(0.05)
    return None


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--gate", default="http://127.0.0.1:8080")
    parser.add_argument("--max-seconds", type=float, default=60.0)
    args = parser.parse_args()
    gate = args.gate.rstrip("/")

    settings = Settings.from_env()
    consumers = ConsumerRegistry(settings.registry_path)
    grants = GrantRegistry(settings.grants_path)

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    drill_id = f"drill-{stamp}"
    failed = False

    def step(msg, ok, detail=""):
        nonlocal failed
        print(f"  {'PASS' if ok else 'FAIL'}  {msg}" + (f" — {detail}" if detail else ""))
        failed = failed or not ok

    print(f"REVOCATION DRILL {drill_id} against {gate}")

    # arm: one throwaway consumer, one throwaway grant
    key = consumers.issue(drill_id, "revocation drill (throwaway)")
    grant_id = grants.issue(drill_id, {"zone": f"{drill_id}-nowhere"}, ttl_hours=1)
    query = lambda: _post(gate + "/query", {"type": "count"}, key)          # noqa: E731
    preview = lambda: _post(gate + "/preview", {"grant_id": grant_id}, key)  # noqa: E731

    status, _ = query()
    step("throwaway key answers queries", status == 200, f"HTTP {status}")
    status, _ = preview()
    step("throwaway grant serves /preview", status == 200, f"HTTP {status}")

    # switch 1: the grant — kills previews, and ONLY previews
    grants.revoke(grant_id)
    t_grant = _time_until_403(preview, args.max_seconds, "grant revoked")
    step("grant revocation bites", t_grant is not None,
         f"{t_grant:.3f}s to 403" if t_grant is not None else "TIMED OUT")
    status, _ = query()
    step("queries SURVIVE grant revocation (grant kill ≠ key kill)",
         status == 200, f"HTTP {status}")

    # switch 2: the consumer — kills everything
    consumers.revoke(drill_id)
    t_consumer = _time_until_403(query, args.max_seconds, "key revoked")
    step("consumer revocation bites", t_consumer is not None,
         f"{t_consumer:.3f}s to 403" if t_consumer is not None else "TIMED OUT")

    # the number goes in the log — drills that aren't recorded didn't happen
    record = {
        "drill_id": drill_id, "gate": gate,
        "ts": datetime.now(timezone.utc).isoformat(),
        "grant_revoke_seconds": t_grant,
        "consumer_revoke_seconds": t_consumer,
        "result": "FAIL" if failed else "PASS",
    }
    log_path = settings.data_dir / "drills.jsonl"
    with log_path.open("a") as f:
        f.write(json.dumps(record, sort_keys=True) + "\n")

    print(f"\nDRILL {'FAIL' if failed else 'PASS'} — logged to {log_path}")
    if not failed:
        print(f"  time-to-revoke: grant {t_grant:.3f}s · consumer {t_consumer:.3f}s "
              f"(criterion: minutes; measured: seconds)")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
