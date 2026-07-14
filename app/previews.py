"""Mode C — degraded, watermarked previews. The negotiation fallback.

This module is the ONLY legitimate caller of BlobVault.open_object().
Every preview is generated on demand inside the gate, never stored
plaintext, and stamped with who it was made for. Per-class rules
(closed taxonomy):

  unstructured images  -> downscaled, recompressed thumbnail with a visible
                          per-consumer watermark
  tabular (csv/tsv)    -> schema card: column names + row count — NEVER
                          sample rows or cell values
  gis (geojson)        -> coarse spatial card: bbox rounded to 0.1 degree
                          (~11 km) + feature count — precise geometry never
                          leaves at ANY mode
  everything else      -> metadata card only (video/audio degradation is
                          v1.x — needs ffmpeg)

Degrade first, watermark always, disclose the minimum that proves value.
"""
import base64
import csv
import io
import json
from typing import Dict, List, Optional

from PIL import Image, ImageDraw

from . import tracemark

PREVIEW_MAX_DIM = 256          # px, longest side
PREVIEW_JPEG_QUALITY = 35      # aggressively recompressed
GIS_COARSE_DECIMALS = 1        # 0.1 degree ≈ 11 km

_THUMBNAIL_EXTS = {".jpg", ".jpeg", ".png", ".webp"}


def make_preview(entry: Dict, payload: bytes, watermark: Dict,
                 trace_key: Optional[bytes] = None) -> Dict:
    """One preview for one object. `watermark` = {consumer_id, grant_id, generated_at}.
    With `trace_key`, image previews additionally carry the keyed INVISIBLE
    mark (app.tracemark) — per-consumer leak attribution."""
    mt, ext = entry["media_type"], entry["ext"]
    try:
        if mt == "unstructured" and ext in _THUMBNAIL_EXTS:
            return _image_thumbnail(entry, payload, watermark, trace_key)
        if mt == "tabular" and ext in (".csv", ".tsv"):
            return _tabular_schema_card(entry, payload, watermark)
        if mt == "gis" and ext == ".geojson":
            return _gis_coarse_card(entry, payload, watermark)
    except Exception:
        # a malformed payload degrades to the safest output, never an error
        # that might echo payload fragments
        pass
    return _metadata_card(entry, watermark)


def _base(entry: Dict, kind: str, watermark: Dict) -> Dict:
    # coarse facts only — never object_id, hash, or filename
    return {
        "kind": kind,
        "media_type": entry["media_type"],
        "zone": entry["zone"],
        "category": entry["category"],
        "captured_at": entry.get("captured_at"),
        "watermark": dict(watermark),
    }


def _image_thumbnail(entry: Dict, payload: bytes, watermark: Dict,
                     trace_key: Optional[bytes] = None) -> Dict:
    img = Image.open(io.BytesIO(payload))
    img.thumbnail((PREVIEW_MAX_DIM, PREVIEW_MAX_DIM))
    img = img.convert("RGB")
    draw = ImageDraw.Draw(img)
    stamp = f"AVA PREVIEW · {watermark['consumer_id']}"
    stamp2 = f"grant {watermark['grant_id'][:8]} · {watermark['generated_at'][:10]}"
    # visible mark, tiled top/middle/bottom so a crop can't cleanly remove it
    w, h = img.size
    for y in (4, h // 2 - 6, h - 24):
        draw.text((4, y), stamp, fill=(255, 255, 255))
        draw.text((4, y + 11), stamp2, fill=(220, 220, 220))
    if trace_key is not None:
        # invisible layer goes on LAST: stripping the visible text (AI
        # inpainting) leaves the tracing mark intact — drill-enforced
        img = tracemark.embed(img, trace_key,
                              watermark["consumer_id"], watermark["grant_id"])
    out = io.BytesIO()
    img.save(out, format="JPEG", quality=PREVIEW_JPEG_QUALITY)
    p = _base(entry, "thumbnail", watermark)
    p["mime"] = "image/jpeg"
    p["data_b64"] = base64.b64encode(out.getvalue()).decode()
    return p


def _tabular_schema_card(entry: Dict, payload: bytes, watermark: Dict) -> Dict:
    delim = "\t" if entry["ext"] == ".tsv" else ","
    text = payload.decode("utf-8", errors="replace")
    reader = csv.reader(io.StringIO(text), delimiter=delim)
    header = next(reader, [])
    row_count = sum(1 for _ in reader)
    p = _base(entry, "card", watermark)
    p["card"] = {
        "columns": header,
        "row_count": row_count,
        "note": "schema only — cell values are never previewed; "
                "coarsened aggregates land in v1.x",
    }
    return p


def _gis_coarse_card(entry: Dict, payload: bytes, watermark: Dict) -> Dict:
    doc = json.loads(payload)
    coords: List[List[float]] = []

    def walk(node):
        if isinstance(node, list):
            if len(node) >= 2 and all(isinstance(v, (int, float)) for v in node[:2]):
                coords.append([float(node[0]), float(node[1])])
            else:
                for item in node:
                    walk(item)
        elif isinstance(node, dict):
            for v in node.values():
                walk(v)

    walk(doc.get("features", doc))
    p = _base(entry, "card", watermark)
    if coords:
        r = GIS_COARSE_DECIMALS
        xs, ys = [c[0] for c in coords], [c[1] for c in coords]
        bbox = [round(min(xs), r), round(min(ys), r), round(max(xs), r), round(max(ys), r)]
    else:
        bbox = None
    p["card"] = {
        "bbox_coarse": bbox,
        "feature_count": len(doc.get("features", [])) if isinstance(doc, dict) else 0,
        "precision_note": f"coordinates coarsened to {10 ** -GIS_COARSE_DECIMALS}° "
                          f"(~11 km); precise geometry never leaves the gate",
    }
    return p


def _metadata_card(entry: Dict, watermark: Dict) -> Dict:
    p = _base(entry, "card", watermark)
    p["card"] = {
        "size_bytes": entry["size_bytes"],
        "note": "metadata only in v1 — degraded excerpts for this class are v1.x",
    }
    return p
