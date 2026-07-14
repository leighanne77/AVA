#!/usr/bin/env python3
"""The watermark REMOVAL drill — attack our own mark, report what survives.

Two tiers, two rules (Terms.md · Watermarking):

  TRIPWIRE — what an honest buyer's tools do (recompress, resize,
  brightness, mild blur) plus visible-mark stripping (simulated
  inpainting). The invisible mark MUST survive every one: any failure
  fails the drill (exit 1).

  MEASURED — alignment-breaking attacks (crops). Reported honestly,
  never promised. AI regeneration attacks can't run in this sandbox at
  all; they are a quarterly manual round with current external tools —
  this drill prints the reminder so the gap is never silent.

Self-contained: synthetic photos, throwaway key, temp sandbox. The drill
RECORD goes to the real data/drills.jsonl — drills that aren't recorded
didn't happen.

Usage:  .venv/bin/python scripts/drill_watermark_removal.py
"""
import base64
import io
import json
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from PIL import Image, ImageEnhance, ImageFilter   # noqa: E402

from app import tracemark                          # noqa: E402
from app.config import Settings                    # noqa: E402
from app.previews import make_preview              # noqa: E402
from scripts.generate_synthetic_media import make_files  # noqa: E402

WRONG_PAIRS = [(f"innocent-{i}", "grant-other") for i in range(10)]


def _jpeg(im, q):
    b = io.BytesIO()
    im.save(b, "JPEG", quality=q)
    return Image.open(io.BytesIO(b.getvalue())).convert("RGB")


def _strip_visible(im):
    """Simulate AI inpainting of the visible mark: overpaint the three
    tiled text bands with the image's median color."""
    im = im.copy()
    w, h = im.size
    for y0, y1 in ((0, 30), (h // 2 - 10, h // 2 + 22), (h - 30, h)):
        im.paste((128, 128, 128), (0, max(0, y0), w, min(h, y1)))
    return im


def attacks(im):
    w, h = im.size
    tripwire = {
        "identity": im,
        "jpeg_q50": _jpeg(im, 50),
        "jpeg_q30": _jpeg(im, 30),
        "resize_75%": im.resize((int(w * .75), int(h * .75))),
        "resize_50%": im.resize((w // 2, h // 2)),
        "brightness_+10%": ImageEnhance.Brightness(im).enhance(1.1),
        "brightness_-10%": ImageEnhance.Brightness(im).enhance(0.9),
        "blur_r1": im.filter(ImageFilter.GaussianBlur(1)),
        "strip_visible_mark": _strip_visible(im),
    }
    measured = {
        "crop_10%": im.crop((w // 10, h // 10, w - w // 10, h - h // 10)),
        "crop_25%": im.crop((w // 4, h // 4, w - w // 4, h - h // 4)),
    }
    return tripwire, measured


def main():
    settings = Settings.from_env()
    sandbox = Path(tempfile.mkdtemp(prefix="ava-wmdrill-"))
    key = tracemark.load_or_create_key(sandbox / "keys")
    consumer, grant = "drill-leaker", "drill-grant-0001"

    print("WATERMARK REMOVAL DRILL — invisible mark vs. the attack battery")
    print(f"  strength={tracemark.STRENGTH} · grid={tracemark.GRID}×{tracemark.GRID} "
          f"· threshold z≥{tracemark.Z_THRESHOLD} · 3 synthetic photos\n")

    rows = {}
    for seed in (1, 2, 3):
        src = sandbox / f"photo-{seed}"
        make_files(src, seed=seed)
        entry = {"media_type": "unstructured", "ext": ".png",
                 "zone": "drill", "category": "drill", "size_bytes": 0,
                 "captured_at": None}
        p = make_preview(entry, (src / "photo.png").read_bytes(),
                         {"consumer_id": consumer, "grant_id": grant,
                          "generated_at": "2026-01-01T00:00:00Z"},
                         trace_key=key)
        served = Image.open(io.BytesIO(base64.b64decode(p["data_b64"])))
        tripwire, measured = attacks(served.convert("RGB"))
        for tier, batch in (("TRIPWIRE", tripwire), ("MEASURED", measured)):
            for name, im in batch.items():
                z_true = tracemark.correlate(im, key, consumer, grant)
                z_wrong = max(tracemark.correlate(im, key, c, g)
                              for c, g in WRONG_PAIRS)
                zt, zw, _ = rows.get(name, (999.0, 0.0, tier))
                rows[name] = (min(zt, z_true), max(zw, z_wrong), tier)

    failed = False
    for name, (z_true, z_wrong, tier) in rows.items():
        detected = z_true >= tracemark.Z_THRESHOLD
        clean = z_wrong < tracemark.Z_THRESHOLD
        ok = detected and clean
        if tier == "TRIPWIRE":
            failed = failed or not ok
            verdict = "PASS" if ok else "FAIL"
        else:
            verdict = "SURVIVES" if ok else "LOST (as designed-for: measured, not promised)"
        print(f"  {tier:8s} {name:20s} z_true(min)={z_true:6.2f}  "
              f"z_wrong(max)={z_wrong:5.2f}   {verdict}")

    print("\n  REMINDER: AI-tier attacks (inpainting models, diffusion "
          "re-render) cannot run in this sandbox.\n  Quarterly manual round: "
          "feed real previews to current removal tools, then run "
          "detect_watermark.py on the results.")

    record = {
        "drill": "watermark_removal",
        "ts": datetime.now(timezone.utc).isoformat(),
        "strength": tracemark.STRENGTH,
        "results": {name: {"z_true_min": round(zt, 2), "z_wrong_max": round(zw, 2),
                           "tier": tier}
                    for name, (zt, zw, tier) in rows.items()},
        "result": "FAIL" if failed else "PASS",
    }
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    log_path = settings.data_dir / "drills.jsonl"
    with log_path.open("a") as f:
        f.write(json.dumps(record, sort_keys=True) + "\n")

    print(f"\nDRILL {'FAIL' if failed else 'PASS'} — logged to {log_path}")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
