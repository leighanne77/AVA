"""The invisible tracing mark — keyed, blind, per-consumer (the tracemark layer).

Kerckhoffs discipline: this file is public; the secrecy lives entirely in
`keys/watermark.key`. The mark is a pseudo-random ±delta pattern on a
16×16 grid of luminance-cell means, seeded by HMAC(key, consumer|grant).
Detection is blind (no original needed) and keyed (without the key, the
mark's PRESENCE is statistically unprovable — a remover cannot confirm
success). Payload identifies the (consumer, grant) pair → leak attribution.

Design bounds, stated honestly (see Terms.md · Watermarking):
  - survives what an honest buyer does to a file (resize, recompress,
    brightness) — the removal drill's tripwire tier enforces this;
  - a strong AI re-render scrubs it — and destroys the image's
    evidentiary value with it; measured, never promised;
  - grid is normalized to the image, so global resize is harmless;
    heavy crops break alignment — measured tier, not guaranteed.
"""
import hashlib
import hmac
import os
from math import sqrt
from pathlib import Path
from typing import Tuple

from PIL import Image

GRID = 24              # pattern cells per side (576 cells; z grows ~√cells)
STRENGTH = 5.0         # luma delta per cell; invisibility budget
DETECT_SIZE = 120      # canonical square for blind detection (24×5px cells)
Z_THRESHOLD = 4.0      # detection claim: z >= 4  (~3e-5 false-positive/pair)
# Constants are calibration-locked (by calibration sweep): worst-case z across
# random keys — visible-strip 5.6, strip+brightness 5.0, benign ≥12, null
# max 2.4. Change them only with a fresh sweep + removal drill.


def load_or_create_key(keys_dir: Path) -> bytes:
    """32-byte watermark master key; owner-side secret, never leaves."""
    path = Path(keys_dir) / "watermark.key"
    if path.exists():
        return path.read_bytes()
    path.parent.mkdir(parents=True, exist_ok=True)
    key = os.urandom(32)
    path.write_bytes(key)
    os.chmod(path, 0o600)
    return key


def _pattern(key: bytes, consumer_id: str, grant_id: str):
    """GRID×GRID of ±1, derived cell-by-cell from the keyed seed — no PRNG
    version drift, pure HMAC."""
    seed = hmac.new(key, f"{consumer_id}|{grant_id}".encode(),
                    hashlib.sha256).digest()
    cells = []
    for i in range(GRID):
        row = []
        for j in range(GRID):
            h = hashlib.sha256(seed + bytes([i, j])).digest()
            row.append(1.0 if h[0] & 1 else -1.0)
        cells.append(row)
    return cells


def embed(img: Image.Image, key: bytes, consumer_id: str,
          grant_id: str, strength: float = STRENGTH) -> Image.Image:
    """Return a copy of `img` carrying the (consumer, grant) mark."""
    pat = _pattern(key, consumer_id, grant_id)
    ycc = img.convert("YCbCr")
    y, cb, cr = ycc.split()
    w, h = img.size
    px = list(y.getdata())
    out = [0] * len(px)
    for yy in range(h):
        gi_row = pat[min(yy * GRID // h, GRID - 1)]
        base = yy * w
        for xx in range(w):
            v = px[base + xx] + strength * gi_row[min(xx * GRID // w, GRID - 1)]
            out[base + xx] = 0 if v < 0 else (255 if v > 255 else int(v + 0.5))
    y2 = Image.new("L", (w, h))
    y2.putdata(out)
    return Image.merge("YCbCr", (y2, cb, cr)).convert("RGB")


def _cell_means(img: Image.Image):
    """GRID×GRID luminance cell means over the canonically-resized image."""
    g = img.convert("L").resize((DETECT_SIZE, DETECT_SIZE))
    px = list(g.getdata())
    step = DETECT_SIZE // GRID
    means = []
    for i in range(GRID):
        row = []
        for j in range(GRID):
            total = 0
            for dy in range(step):
                base = (i * step + dy) * DETECT_SIZE + j * step
                total += sum(px[base:base + step])
            row.append(total / (step * step))
        means.append(row)
    return means


def correlate(img: Image.Image, key: bytes, consumer_id: str,
              grant_id: str) -> float:
    """Blind detection statistic. Under no-mark/wrong-key, z ~ N(0,1);
    the embedded pair scores far above Z_THRESHOLD.

    Residuals are winsorized at 3×MAD: hard image edges (or an attacker's
    overpainted bands) otherwise produce a few huge residuals that both
    drown the signal and fatten the null tail. Clipping keeps every cell's
    vote bounded — robust statistics, not a tuning knob."""
    pat = _pattern(key, consumer_id, grant_id)
    m = _cell_means(img)
    pairs = []
    for i in range(GRID):
        for j in range(GRID):
            # high-pass: neighbors' average strips image content, and the
            # neighbors' own ±1 cells average out in expectation
            neigh = []
            if i > 0:
                neigh.append(m[i - 1][j])
            if i < GRID - 1:
                neigh.append(m[i + 1][j])
            if j > 0:
                neigh.append(m[i][j - 1])
            if j < GRID - 1:
                neigh.append(m[i][j + 1])
            pairs.append((m[i][j] - sum(neigh) / len(neigh), pat[i][j]))

    absr = sorted(abs(r) for r, _ in pairs)
    mad = absr[len(absr) // 2]
    clip = 3 * 1.4826 * mad if mad > 0 else float("inf")
    num, den = 0.0, 0.0
    for r, p in pairs:
        r = max(-clip, min(clip, r))
        num += r * p
        den += r * r
    return num / sqrt(den) if den > 0 else 0.0


def detect(img: Image.Image, key: bytes, consumer_id: str,
           grant_id: str) -> Tuple[bool, float]:
    z = correlate(img, key, consumer_id, grant_id)
    return z >= Z_THRESHOLD, z
