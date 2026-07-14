#!/usr/bin/env python3
"""OWNER-side leak attribution: who leaked this image, under which grant?

Feed it a suspect image found in the wild. Without --consumer-id/--grant-id
it tests every (consumer, grant) pair ever issued (from the grants
registry — revoked and expired included: leaks outlive grants) and ranks
them. Detection is keyed and blind: needs keys/watermark.key and the
image, nothing else — no original, no vault access.

Usage:
  .venv/bin/python scripts/detect_watermark.py --image suspect.jpg
  .venv/bin/python scripts/detect_watermark.py --image suspect.jpg \
      --consumer-id acme --grant-id <uuid>        # test one hypothesis

Exit 0 = attribution made (z >= threshold); exit 1 = no pair detected.
"""
import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from PIL import Image                       # noqa: E402

from app import tracemark                   # noqa: E402
from app.config import Settings             # noqa: E402
from app.grants import GrantRegistry        # noqa: E402


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--image", required=True, help="suspect image file")
    parser.add_argument("--consumer-id", default=None)
    parser.add_argument("--grant-id", default=None)
    parser.add_argument("--top", type=int, default=5,
                        help="show the N best-scoring pairs")
    args = parser.parse_args()

    settings = Settings.from_env()
    key = tracemark.load_or_create_key(settings.keys_dir)
    img = Image.open(args.image).convert("RGB")

    if args.consumer_id and args.grant_id:
        candidates = [(args.consumer_id, args.grant_id)]
    else:
        grants = GrantRegistry(settings.grants_path).list_grants()
        candidates = [(g["consumer_id"], gid) for gid, g in grants.items()]
        if not candidates:
            print("no grants on record — nothing to test against")
            sys.exit(1)

    scored = sorted(
        ((tracemark.correlate(img, key, cid, gid), cid, gid)
         for cid, gid in candidates), reverse=True)

    print(f"tested {len(scored)} (consumer, grant) pair(s); "
          f"threshold z ≥ {tracemark.Z_THRESHOLD}")
    for z, cid, gid in scored[:args.top]:
        flag = "  ← DETECTED" if z >= tracemark.Z_THRESHOLD else ""
        print(f"  z={z:7.2f}   {cid}   grant {gid}{flag}")

    best_z, best_cid, best_gid = scored[0]
    if best_z >= tracemark.Z_THRESHOLD:
        print(f"\nATTRIBUTION: consumer '{best_cid}' under grant {best_gid} "
              f"(z={best_z:.2f}). The audit log has the serve record.")
        sys.exit(0)
    print("\nNO ATTRIBUTION: no pair reaches the threshold — image is "
          "unmarked, heavily transformed, or not from this gate.")
    sys.exit(1)


if __name__ == "__main__":
    main()
