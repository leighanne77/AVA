#!/usr/bin/env python3
"""Ingest media files (or a directory) into the encrypted blob vault.

Usage:
  .venv/bin/python scripts/ingest_media.py --path field-batch/ --zone zone-03 --category alpha
  .venv/bin/python scripts/ingest_media.py --path survey.tif --media-type gis --zone zone-01 --category beta

Unknown extensions are refused unless --media-type names a class — the gate
never guesses a sensitivity profile.
"""
import argparse
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.blobvault import BlobVault            # noqa: E402
from app.config import Settings                # noqa: E402
from app.keyrelease import make_key_release    # noqa: E402
from app.media import MEDIA_TYPES, ClassificationError  # noqa: E402


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--path", required=True, help="file or directory")
    parser.add_argument("--zone", required=True)
    parser.add_argument("--category", required=True)
    parser.add_argument("--quality", default="ok")
    parser.add_argument("--captured-at", default=None,
                        help="ISO timestamp; defaults to file mtime")
    parser.add_argument("--media-type", default=None, choices=MEDIA_TYPES,
                        help="override / required for unmapped extensions")
    args = parser.parse_args()

    settings = Settings.from_env()
    settings.ensure_dirs()
    vault = BlobVault(settings.vault_dir, make_key_release(settings))

    root = Path(args.path)
    files = sorted(p for p in ([root] if root.is_file() else root.rglob("*")) if p.is_file())
    if not files:
        print(f"nothing to ingest at {root}")
        sys.exit(1)

    ingested = Counter()
    skipped = []
    for f in files:
        captured = args.captured_at or datetime.fromtimestamp(
            f.stat().st_mtime, tz=timezone.utc).isoformat()
        try:
            entry = vault.put(f.read_bytes(), f.suffix,
                              zone=args.zone, category=args.category,
                              quality=args.quality, captured_at=captured,
                              media_type_override=args.media_type)
            ingested[entry["media_type"]] += 1
        except ClassificationError as exc:
            skipped.append((f.name, str(exc)))

    print(f"ingested {sum(ingested.values())} object(s): "
          + ", ".join(f"{k}={v}" for k, v in sorted(ingested.items())))
    if skipped:
        print(f"SKIPPED {len(skipped)} (unmapped extension — rerun with --media-type):")
        for name, why in skipped:
            print(f"  {name}: {why}")
    print(f"blob vault now holds {vault.object_count()} objects (encrypted)")


if __name__ == "__main__":
    main()
