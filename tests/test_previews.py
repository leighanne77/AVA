"""Mode C previews: degraded, watermarked, minimum disclosure per class."""
import base64
import io
import json

from PIL import Image

from app.previews import PREVIEW_MAX_DIM, make_preview

WM = {"consumer_id": "consumer-x", "grant_id": "abcd1234-0000-0000-0000-000000000000",
      "generated_at": "2026-07-10T20:00:00+00:00"}


def _entry(media_type, ext, **kw):
    base = {"object_id": "test-oid-000", "media_type": media_type, "mime": "x", "ext": ext,
            "size_bytes": 1234, "sha256_plain": "ff" * 32,
            "captured_at": "2026-06-01T00:00:00+00:00", "zone": "zone-01",
            "category": "alpha", "quality": "ok"}
    base.update(kw)
    return base


def _png(w=800, h=600, color=(200, 30, 30)) -> bytes:
    buf = io.BytesIO()
    Image.new("RGB", (w, h), color).save(buf, format="PNG")
    return buf.getvalue()


# ---- images ----

def test_image_preview_is_downscaled_recompressed_and_marked():
    original = _png()
    p = make_preview(_entry("unstructured", ".png"), original, WM)
    assert p["kind"] == "thumbnail" and p["mime"] == "image/jpeg"
    out = base64.b64decode(p["data_b64"])
    assert out != original
    img = Image.open(io.BytesIO(out))
    # degradation = resolution, not byte count (a solid-color PNG can be
    # tiny while its watermarked JPEG is larger): 800x600 in, <=256 out
    assert max(img.size) <= PREVIEW_MAX_DIM
    assert img.size != (800, 600)
    # the original is one solid color; the watermark text must have added others
    assert len(set(img.convert("RGB").getdata())) > 1
    assert p["watermark"]["consumer_id"] == "consumer-x"


def test_corrupt_image_degrades_to_metadata_card():
    p = make_preview(_entry("unstructured", ".jpg"), b"not an image at all", WM)
    assert p["kind"] == "card"
    assert "not an image" not in json.dumps(p)  # no payload echo, ever


# ---- tabular ----

def test_tabular_card_has_schema_never_values():
    payload = b"site,metric,reading\nS-001,biomass,42.7\nS-002,biomass,58.1\n"
    p = make_preview(_entry("tabular", ".csv"), payload, WM)
    assert p["card"]["columns"] == ["site", "metric", "reading"]
    assert p["card"]["row_count"] == 2
    flat = json.dumps(p)
    for secret in ("S-001", "42.7", "58.1", "biomass"):
        assert secret not in flat


# ---- gis ----

def test_gis_card_coarsens_coordinates():
    payload = json.dumps({"type": "FeatureCollection", "features": [
        {"type": "Feature", "geometry": {"type": "Point",
                                         "coordinates": [-70.123456, -0.987654]}},
        {"type": "Feature", "geometry": {"type": "Point",
                                         "coordinates": [-70.654321, -1.234567]}},
    ]}).encode()
    p = make_preview(_entry("gis", ".geojson"), payload, WM)
    card = p["card"]
    assert card["feature_count"] == 2
    assert card["bbox_coarse"] == [-70.7, -1.2, -70.1, -1.0]
    flat = json.dumps(p)
    for precise in ("-70.123456", "-0.987654", "-70.654321", "-1.234567"):
        assert precise not in flat


def test_gis_shapefile_gets_card_not_parse():
    p = make_preview(_entry("gis", ".shp"), b"\x00\x00\x27\x0a binary shapefile", WM)
    assert p["kind"] == "card" and "size_bytes" in p["card"]


# ---- other classes ----

def test_video_audio_get_metadata_cards_only():
    for mt, ext in (("video", ".mp4"), ("audio", ".wav")):
        p = make_preview(_entry(mt, ext), b"\x00" * 100, WM)
        assert p["kind"] == "card"
        assert p["card"]["size_bytes"] == 1234


def test_no_identifier_leak_in_any_preview():
    cases = [
        (_entry("unstructured", ".png"), _png()),
        (_entry("tabular", ".csv"), b"a,b\n1,2\n"),
        (_entry("gis", ".geojson"), b'{"type":"FeatureCollection","features":[]}'),
        (_entry("video", ".mp4"), b"\x00" * 10),
    ]
    for entry, payload in cases:
        flat = json.dumps(make_preview(entry, payload, WM))
        assert entry["object_id"] not in flat
        assert entry["sha256_plain"] not in flat
        assert '"ext"' not in flat
