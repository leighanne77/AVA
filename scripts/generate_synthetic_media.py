#!/usr/bin/env python3
"""Generate a synthetic media set covering ALL FIVE classes — drill fuel.

Writes six small files (video, audio, tabular, unstructured ×2, gis) into
--dir. Content is synthetic and deterministic per --seed; the tabular and
gis files embed leak markers (hyphenated, 5+ chars — impossible in base64)
so drills can scan the encrypted vault and PROVE plaintext never landed.

Usage:  .venv/bin/python scripts/generate_synthetic_media.py --dir data/synthetic_media
"""
import argparse
import io
import json
import random
import struct
import wave
from pathlib import Path

from PIL import Image, ImageDraw

# Deliberately base64-impossible (hyphens, length) — see conftest rationale.
LEAK_MARKERS = ["synthetic-marker-tabular", "synthetic-marker-geometry"]


def make_files(out: Path, seed: int) -> list:
    rng = random.Random(seed)
    out.mkdir(parents=True, exist_ok=True)
    written = []

    def put(name: str, data: bytes):
        (out / name).write_bytes(data)
        written.append(name)

    # video — the gate classifies by extension and never parses payloads,
    # so a synthetic clip is opaque bytes (real footage stays out of drills)
    put("clip.mp4", bytes([rng.randrange(256) for _ in range(4096)]))

    # audio — a real, playable WAV: 1s mono 8kHz sine-ish wobble
    buf = io.BytesIO()
    with wave.open(buf, "wb") as w:
        w.setnchannels(1); w.setsampwidth(2); w.setframerate(8000)
        w.writeframes(b"".join(
            struct.pack("<h", int(12000 * ((i % 64) / 32 - 1)))
            for i in range(8000)))
    put("song.wav", buf.getvalue())

    # tabular — carries a leak marker for the no-plaintext scan
    rows = [f"{LEAK_MARKERS[0]},obs-{i:03d},{rng.uniform(0, 100):.2f}"
            for i in range(20)]
    put("table.csv", ("marker,observation,value\n" + "\n".join(rows)).encode())

    # unstructured ×2 — a real PNG (so Mode C makes a real thumbnail)…
    img = Image.new("RGB", (640, 480),
                    tuple(rng.randrange(64, 224) for _ in range(3)))
    d = ImageDraw.Draw(img)
    for _ in range(12):
        x, y = rng.randrange(640), rng.randrange(480)
        d.ellipse([x, y, x + rng.randrange(20, 120), y + rng.randrange(20, 120)],
                  fill=tuple(rng.randrange(256) for _ in range(3)))
    pbuf = io.BytesIO(); img.save(pbuf, "PNG")
    put("photo.png", pbuf.getvalue())
    # …and a minimal single-page PDF (metadata-card class in v1)
    put("notes.pdf",
        b"%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n"
        b"2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n"
        b"3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 200 200]>>endobj\n"
        b"trailer<</Root 1 0 R>>\n%%EOF\n")

    # gis — highest sensitivity class; carries the second leak marker
    put("area.geojson", json.dumps({
        "type": "FeatureCollection",
        "features": [{
            "type": "Feature",
            "properties": {"name": LEAK_MARKERS[1]},
            "geometry": {"type": "Polygon", "coordinates": [[
                [round(rng.uniform(-1, 1), 5), round(rng.uniform(-1, 1), 5)]
                for _ in range(4)]]},
        }],
    }).encode())

    return written


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dir", required=True, help="output directory")
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()
    written = make_files(Path(args.dir), args.seed)
    print(f"wrote {len(written)} synthetic media files to {args.dir}: "
          + ", ".join(written))
    print("classes covered: video, audio, tabular, unstructured (png+pdf), gis")


if __name__ == "__main__":
    main()
