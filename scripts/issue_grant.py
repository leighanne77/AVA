#!/usr/bin/env python3
"""OWNER-side: issue a time-boxed sample grant for Mode C previews.

Usage:
  .venv/bin/python scripts/issue_grant.py --consumer-id consumer-001 \
      --hours 48 --media-type unstructured --zone zone-03
"""
import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.config import Settings          # noqa: E402
from app.consumers import ConsumerRegistry  # noqa: E402
from app.grants import GrantRegistry     # noqa: E402
from app.media import MEDIA_TYPES        # noqa: E402


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--consumer-id", required=True)
    parser.add_argument("--hours", type=float, required=True,
                        help="grant lifetime; keep short — this is a teaser, not access")
    parser.add_argument("--media-type", default=None, choices=MEDIA_TYPES)
    parser.add_argument("--zone", default=None)
    parser.add_argument("--category", default=None)
    parser.add_argument("--ts-from", default=None)
    parser.add_argument("--ts-to", default=None)
    args = parser.parse_args()

    settings = Settings.from_env()
    settings.ensure_dirs()

    consumers = ConsumerRegistry(settings.registry_path).list_consumers()
    if args.consumer_id not in consumers:
        print(f"unknown consumer '{args.consumer_id}' — issue their key first", file=sys.stderr)
        sys.exit(1)

    grants = GrantRegistry(settings.grants_path)
    grant_id = grants.issue(args.consumer_id, {
        "media_type": args.media_type, "zone": args.zone,
        "category": args.category, "ts_from": args.ts_from, "ts_to": args.ts_to,
    }, ttl_hours=args.hours)
    grant = grants.list_grants()[grant_id]
    print(f"grant issued to '{args.consumer_id}': {grant_id}")
    print(f"  scope:   {grant['filters'] or 'ALL media (consider narrowing)'}")
    print(f"  expires: {grant['expires_at']}")


if __name__ == "__main__":
    main()
