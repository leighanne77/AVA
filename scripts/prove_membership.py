#!/usr/bin/env python3
"""OWNER-side: produce an offline-verifiable proof that one object belongs
to an attested set.

The set is defined by the SAME filters the consumer's attest query used —
they're recorded verbatim in the audit log entry for that query. The vault
is append-only, so if objects were ingested since the attest, the recomputed
root will differ; re-attest or prove against the original population.

Usage:
  .venv/bin/python scripts/prove_membership.py --object-id <uuid> \
      --media-type gis --zone zone-02 > proof.json
"""
import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.blobvault import BlobVault           # noqa: E402
from app.config import Settings               # noqa: E402
from app.keyrelease import make_key_release   # noqa: E402
from app.merkle import merkle_proof, merkle_root_hex  # noqa: E402


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--object-id", required=True)
    parser.add_argument("--media-type", default=None)
    parser.add_argument("--zone", default=None)
    parser.add_argument("--category", default=None)
    parser.add_argument("--ts-from", default=None)
    parser.add_argument("--ts-to", default=None)
    args = parser.parse_args()

    settings = Settings.from_env()
    vault = BlobVault(settings.vault_dir, make_key_release(settings))

    def matched_entries():
        # reuse the gate's own matching by asking for the same set
        for e in vault.iter_index():
            if args.media_type and e["media_type"] != args.media_type:
                continue
            if args.zone and e["zone"] != args.zone:
                continue
            if args.category and e["category"] != args.category:
                continue
            ts = e.get("captured_at")
            if (args.ts_from or args.ts_to) and ts is None:
                continue
            if args.ts_from and ts < args.ts_from:
                continue
            if args.ts_to and ts > args.ts_to:
                continue
            yield e

    entries = list(matched_entries())
    target = next((e for e in entries if e["object_id"] == args.object_id), None)
    if target is None:
        print(f"object {args.object_id} is not in the filtered set "
              f"({len(entries)} matched)", file=sys.stderr)
        sys.exit(1)

    hashes = [e["sha256_plain"] for e in entries]
    proof = {
        "object_id": target["object_id"],
        "sha256_plain": target["sha256_plain"],
        "merkle_root": merkle_root_hex(hashes),
        "set_size": len(hashes),
        "proof": merkle_proof(hashes, target["sha256_plain"]),
    }
    print(json.dumps(proof, indent=2))


if __name__ == "__main__":
    main()
