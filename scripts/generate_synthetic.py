#!/usr/bin/env python3
"""Generate synthetic records and ingest them into the (encrypted) vault.

Usage:  .venv/bin/python scripts/generate_synthetic.py --n 500 --seed 42
"""
import argparse
import random
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.config import Settings           # noqa: E402
from app.keyrelease import make_key_release  # noqa: E402
from app.vault import Vault               # noqa: E402

CATEGORIES = ["alpha", "beta", "gamma", "delta"]
ZONES = [f"zone-{i:02d}" for i in range(1, 9)]
QUALITY = ["ok", "good", "excellent"]


def make_records(n: int, seed: int):
    rng = random.Random(seed)
    now = datetime.now(timezone.utc)
    records = []
    for _ in range(n):
        ts = now - timedelta(days=rng.uniform(0, 730), seconds=rng.uniform(0, 86400))
        records.append({
            "id": str(uuid.UUID(int=rng.getrandbits(128))),
            "ts": ts.isoformat(),
            "category": rng.choice(CATEGORIES),
            "zone": rng.choice(ZONES),
            "value": round(rng.uniform(0.1, 1000.0), 3),
            "quality": rng.choice(QUALITY),
        })
    return records


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--n", type=int, default=500)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    settings = Settings.from_env()
    settings.ensure_dirs()
    vault = Vault(settings.vault_dir, make_key_release(settings))
    count = vault.ingest(make_records(args.n, args.seed))
    print(f"ingested {count} synthetic records "
          f"(vault now holds {vault.record_count()}, encrypted at {settings.vault_dir})")


if __name__ == "__main__":
    main()
