#!/usr/bin/env python3
"""Issue a consumer key (owner-side, out-of-band — never a network endpoint).

Usage:  .venv/bin/python scripts/issue_consumer_key.py --id consumer-001 --label "Pilot consumer"
The key is printed exactly once. Only its hash is stored.
"""
import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.config import Settings        # noqa: E402
from app.consumers import ConsumerRegistry  # noqa: E402


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--id", required=True, dest="consumer_id")
    parser.add_argument("--label", default="")
    parser.add_argument("--trusted", action="store_true",
                        help="grant the attest privilege (commitments reveal "
                             "dataset size/shape — default is untrusted)")
    args = parser.parse_args()

    settings = Settings.from_env()
    settings.ensure_dirs()
    registry = ConsumerRegistry(settings.registry_path)
    key = registry.issue(args.consumer_id, args.label, trusted=args.trusted)
    print(f"consumer '{args.consumer_id}' issued "
          f"({'TRUSTED — attest enabled' if args.trusted else 'untrusted — attest refused'}).")
    print("KEY (shown once, store it now):")
    print(f"  {key}")


if __name__ == "__main__":
    main()
