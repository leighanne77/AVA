#!/usr/bin/env python3
"""CONSUMER-side: verify a membership proof against an attested root.

Needs NOTHING from the vault — no keys, no access, no network. Just the
proof file (from the owner) and the root (from the consumer's own earlier
attest answer). If the roots match and the proof folds true, the object
was in the attested set, unmodified.

Usage:
  .venv/bin/python scripts/verify_membership.py --proof proof.json \
      --root <merkle_root from the attest answer>
"""
import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.merkle import verify_membership  # noqa: E402


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--proof", required=True, help="proof JSON file")
    parser.add_argument("--root", required=True, help="attested merkle root (hex)")
    args = parser.parse_args()

    proof = json.loads(Path(args.proof).read_text())
    if proof["merkle_root"] != args.root:
        print("MISMATCH: proof was built against a different root "
              "(set changed since the attest, or wrong attest answer).")
        sys.exit(1)
    ok = verify_membership(proof["sha256_plain"], proof["proof"], args.root)
    if ok:
        print(f"VERIFIED: object {proof['object_id']} (sha256 {proof['sha256_plain'][:16]}…) "
              f"is in the attested set of {proof['set_size']}.")
    else:
        print("FAILED: proof does not fold to the attested root.")
        sys.exit(1)


if __name__ == "__main__":
    main()
