#!/usr/bin/env python3
"""OWNER-side: grant or revoke a consumer's TRUSTED status.

Trusted gates exactly one thing: `attest` queries. Merkle commitments are
safe but not free — they confirm dataset size/shape over time — so they
are an owner-granted privilege, off by default.
Like key revocation, the change bites on the running gate within one
request (mtime-reload registry).

Usage:
  .venv/bin/python scripts/set_trusted.py --id consumer-001          # grant
  .venv/bin/python scripts/set_trusted.py --id consumer-001 --revoke # remove
"""
import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.config import Settings              # noqa: E402
from app.consumers import ConsumerRegistry   # noqa: E402


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--id", required=True, dest="consumer_id")
    parser.add_argument("--revoke", action="store_true",
                        help="remove trusted status instead of granting it")
    args = parser.parse_args()

    settings = Settings.from_env()
    registry = ConsumerRegistry(settings.registry_path)
    trusted = not args.revoke
    if not registry.set_trusted(args.consumer_id, trusted):
        print(f"unknown consumer '{args.consumer_id}'", file=sys.stderr)
        sys.exit(1)
    if trusted:
        print(f"consumer '{args.consumer_id}' is now TRUSTED — attest enabled. "
              "Commitments will reveal dataset size/shape to them over time.")
    else:
        print(f"consumer '{args.consumer_id}' trust REVOKED — attest refused "
              "from the next request.")


if __name__ == "__main__":
    main()
