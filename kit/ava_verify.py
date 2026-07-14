#!/usr/bin/env python3
"""AVA consumer verification — run this before trusting any answer.

You should have received three things from the data owner:
  1. the gate URL            (e.g. https://gate.example.org)
  2. your bearer key         (starts with "ava_" — keep it secret)
  3. audit_signing.pub       (the gate's audit public key, PEM)

This script checks, in order:
  [1] the gate is reachable and reports its mode           GET  /healthz
  [2] the gate's identity: the audit public key it serves
      matches the copy the owner handed you out-of-band    GET  /attestation
      (enclave mode additionally requires an attestation
      token; full token verification against the pinned
      image digest arrives with the enclave rollout)
  [3] your key works, and the response is answers-only —
      exactly the documented fields, nothing else          POST /query

Requires only Python 3.9+. No packages, no repo checkout.

Usage:
  python3 ava_verify.py --gate http://127.0.0.1:8080 \
      --key ava_yourkey --audit-pub audit_signing.pub

Exit code 0 = every check passed (warnings possible in dev mode); 1 = failed.
"""
import argparse
import base64
import hashlib
import json
import sys
import urllib.error
import urllib.request

TIMEOUT = 10  # seconds per request

# The complete, closed set of fields a query response may carry. Anything
# beyond these is a red flag — answers-only is the product's core promise.
ALLOWED_RESPONSE_KEYS = {"answer", "query_id", "computed_at",
                         "audit_entry_hash", "gate_version"}
ALLOWED_ANSWER_KEYS = {"type", "result", "matched"}


def _http(url: str, body: dict = None, key: str = None):
    """GET (body=None) or POST json. Returns (status, parsed-json | text)."""
    headers = {"Content-Type": "application/json"}
    if key:
        headers["Authorization"] = "Bearer " + key
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            return resp.status, json.loads(resp.read().decode())
    except urllib.error.HTTPError as exc:
        try:
            payload = json.loads(exc.read().decode())
        except Exception:
            payload = {}
        return exc.code, payload
    except (urllib.error.URLError, OSError) as exc:
        return None, str(exc)


def pem_fingerprint(pem_text: str) -> str:
    """SHA-256 over the DER body of a PEM key — whitespace/armor independent.
    Must match app.auditlog.public_key_fingerprint on the gate side."""
    body = "".join(line for line in pem_text.splitlines()
                   if line and not line.startswith("-----"))
    return hashlib.sha256(base64.b64decode(body)).hexdigest()


class Report:
    def __init__(self):
        self.failed = False

    def ok(self, msg):
        print(f"  PASS  {msg}")

    def warn(self, msg):
        print(f"  WARN  {msg}")

    def fail(self, msg):
        print(f"  FAIL  {msg}")
        self.failed = True


def check_health(gate: str, rpt: Report) -> str:
    """Returns the gate's mode ('' on failure)."""
    print("[1/3] Reachability — GET /healthz")
    status, body = _http(gate + "/healthz")
    if status != 200:
        rpt.fail(f"gate unreachable or unhealthy ({status}: {body})")
        return ""
    mode = body.get("mode", "")
    rpt.ok(f"gate is up — mode={mode!r}, version={body.get('version')!r}")
    if mode == "local":
        rpt.warn("LOCAL DEV MODE: no enclave, no attestation — the gate "
                 "claims NO protection. Fine for a drill; not for real data.")
    return mode


def check_identity(gate: str, mode: str, audit_pub_path: str, rpt: Report):
    print("[2/3] Identity — GET /attestation + audit key fingerprint")
    try:
        with open(audit_pub_path) as f:
            local_fp = pem_fingerprint(f.read())
    except (OSError, ValueError) as exc:
        rpt.fail(f"cannot read/parse your copy of the audit key: {exc}")
        return
    status, body = _http(gate + "/attestation")
    if status != 200:
        rpt.fail(f"/attestation returned {status}: {body}")
        return
    if mode == "enclave" and not body.get("attestation"):
        rpt.fail("enclave mode but no attestation token — do not trust "
                 "this gate.")
        return
    served = body.get("audit_pub_pem")
    if not served:
        rpt.fail("gate did not serve its audit public key")
        return
    try:
        served_fp = pem_fingerprint(served)
    except ValueError as exc:
        rpt.fail(f"gate served an unparseable audit key: {exc}")
        return
    if served_fp != local_fp:
        rpt.fail("AUDIT KEY MISMATCH — the gate you reached does not hold "
                 "the key the owner published.\n"
                 f"        yours:  {local_fp}\n"
                 f"        served: {served_fp}\n"
                 "        Stop here and contact the owner out-of-band.")
        return
    rpt.ok(f"audit key fingerprint matches your copy ({local_fp[:16]}…)")
    if mode != "enclave":
        rpt.warn("no attestation token in dev mode — image-digest "
                 "verification activates with the enclave rollout.")


def check_first_query(gate: str, key: str, rpt: Report):
    print("[3/3] First query — POST /query {\"type\": \"count\"}")
    status, body = _http(gate + "/query", body={"type": "count"}, key=key)
    if status == 401:
        rpt.fail("key rejected (401) — wrong key, or ask the owner to issue "
                 "one.")
        return
    if status == 403:
        rpt.fail("key REVOKED (403) — the owner has switched you off; "
                 "contact them.")
        return
    if status != 200:
        rpt.fail(f"query failed ({status}: {body})")
        return
    extra = set(body) - ALLOWED_RESPONSE_KEYS
    extra_ans = set(body.get("answer", {})) - ALLOWED_ANSWER_KEYS
    if extra or extra_ans:
        rpt.fail(f"response carries undocumented fields {extra | extra_ans} "
                 "— answers-only violated; do not proceed, report this.")
        return
    rpt.ok(f"answer received: {body['answer']} — and nothing but an answer")
    rpt.ok("your receipt (save it — it pins this query in the owner's "
           "tamper-evident audit log):")
    print(f"          query_id:         {body['query_id']}")
    print(f"          computed_at:      {body['computed_at']}")
    print(f"          audit_entry_hash: {body['audit_entry_hash']}")


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--gate", required=True, help="gate base URL")
    p.add_argument("--key", required=True, help="your bearer key (ava_…)")
    p.add_argument("--audit-pub", required=True,
                   help="path to the audit_signing.pub the owner gave you")
    args = p.parse_args(argv)
    gate = args.gate.rstrip("/")

    print(f"AVA consumer verification — {gate}")
    rpt = Report()
    mode = check_health(gate, rpt)
    if not rpt.failed:
        check_identity(gate, mode, args.audit_pub, rpt)
    if not rpt.failed:
        check_first_query(gate, args.key, rpt)

    if rpt.failed:
        print("\nRESULT: FAILED — do not rely on this gate until resolved.")
        return 1
    print("\nRESULT: VERIFIED — gate reachable, identity checked, "
          "key live, answers-only intact.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
