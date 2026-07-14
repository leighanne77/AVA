#!/usr/bin/env python3
"""Revoke a consumer's access — the owner's switch. Takes effect on the
running gate within one request (registry mtime check).

Usage:  .venv/bin/python scripts/revoke_consumer.py --id consumer-001
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
    args = parser.parse_args()

    settings = Settings.from_env()
    registry = ConsumerRegistry(settings.registry_path)
    if registry.revoke(args.consumer_id):
        print(f"consumer '{args.consumer_id}' REVOKED. Access is dead everywhere, now.")
    else:
        print(f"consumer '{args.consumer_id}' not found or already revoked.")
        sys.exit(1)


if __name__ == "__main__":
    main()
