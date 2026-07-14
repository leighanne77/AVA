#!/usr/bin/env python3
"""OWNER-side: push the local ciphertext vault to the bucket, or pull it.

Only vault_dir travels — encrypted records/media and wrapped DEKs.
Registries, grants, audit log, and every key stay on the owner's machine
by construction (they live outside vault_dir).

Usage:
  .venv/bin/python scripts/vault_sync.py --push [--bucket gs-bucket-name]
  .venv/bin/python scripts/vault_sync.py --pull [--bucket gs-bucket-name]

Bucket default: $AVA_VAULT_BUCKET.
"""
import argparse
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import bucketsync            # noqa: E402
from app.config import Settings       # noqa: E402


def main():
    parser = argparse.ArgumentParser()
    direction = parser.add_mutually_exclusive_group(required=True)
    direction.add_argument("--push", action="store_true")
    direction.add_argument("--pull", action="store_true")
    parser.add_argument("--bucket", default=os.environ.get("AVA_VAULT_BUCKET", ""))
    args = parser.parse_args()

    if not args.bucket:
        print("set --bucket or AVA_VAULT_BUCKET", file=sys.stderr)
        sys.exit(2)

    settings = Settings.from_env()
    if args.push:
        moved = bucketsync.push(settings.vault_dir, args.bucket)
        print(f"pushed {len(moved)} ciphertext object(s) to "
              f"gs://{args.bucket}/{bucketsync.BUCKET_PREFIX}")
    else:
        moved = bucketsync.pull(args.bucket, settings.vault_dir)
        print(f"pulled {len(moved)} ciphertext object(s) into {settings.vault_dir}")
    for rel in moved:
        print(f"  {rel}")


if __name__ == "__main__":
    main()
