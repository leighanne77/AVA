#!/usr/bin/env python3
"""OWNER-side: revoke a sample grant. Bites within one request.

Usage:  .venv/bin/python scripts/revoke_grant.py --grant-id <uuid>
"""
import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.config import Settings      # noqa: E402
from app.grants import GrantRegistry  # noqa: E402


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--grant-id", required=True)
    args = parser.parse_args()

    grants = GrantRegistry(Settings.from_env().grants_path)
    if grants.revoke(args.grant_id):
        print(f"grant {args.grant_id} REVOKED.")
    else:
        print(f"grant {args.grant_id} not found or already revoked.")
        sys.exit(1)


if __name__ == "__main__":
    main()
