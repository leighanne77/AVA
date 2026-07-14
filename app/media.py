"""The media taxonomy — a closed, five-class set.

Like query types, extending this taxonomy is a design decision, not a
default: every class carries its own Mode C preview rules (Day 2) and its
own sensitivity profile. GIS is the highest-sensitivity class — precise
geometry never leaves the gate at any access mode; previews coarsen to
centroid/bounding-box at reduced precision.

Classification is by explicit extension mapping. Unknown extensions are
refused unless the caller names a class — silent guessing is how the wrong
sensitivity profile gets applied.
"""
from typing import Optional, Tuple

MEDIA_TYPES = ("video", "audio", "tabular", "unstructured", "gis")

# extension -> (media_type, mime). GIS extensions take precedence over
# generic ones (a .geojson is GIS, never "just a json document").
_EXT_MAP = {
    # video
    ".mp4":  ("video", "video/mp4"),
    ".mov":  ("video", "video/quicktime"),
    ".webm": ("video", "video/webm"),
    ".avi":  ("video", "video/x-msvideo"),
    ".mkv":  ("video", "video/x-matroska"),
    # audio
    ".wav":  ("audio", "audio/wav"),
    ".mp3":  ("audio", "audio/mpeg"),
    ".flac": ("audio", "audio/flac"),
    ".ogg":  ("audio", "audio/ogg"),
    ".m4a":  ("audio", "audio/mp4"),
    # tabular / digital
    ".csv":     ("tabular", "text/csv"),
    ".tsv":     ("tabular", "text/tab-separated-values"),
    ".xlsx":    ("tabular", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"),
    ".parquet": ("tabular", "application/vnd.apache.parquet"),
    # unstructured / digital (pdfs, photos, scans, docs)
    ".pdf":  ("unstructured", "application/pdf"),
    ".jpg":  ("unstructured", "image/jpeg"),
    ".jpeg": ("unstructured", "image/jpeg"),
    ".png":  ("unstructured", "image/png"),
    ".heic": ("unstructured", "image/heic"),
    ".webp": ("unstructured", "image/webp"),
    ".docx": ("unstructured", "application/vnd.openxmlformats-officedocument.wordprocessingml.document"),
    ".txt":  ("unstructured", "text/plain"),
    # GIS — highest sensitivity
    ".geojson": ("gis", "application/geo+json"),
    ".shp":     ("gis", "application/octet-stream"),
    ".kml":     ("gis", "application/vnd.google-earth.kml+xml"),
    ".kmz":     ("gis", "application/vnd.google-earth.kmz"),
    ".gpx":     ("gis", "application/gpx+xml"),
    ".gpkg":    ("gis", "application/geopackage+sqlite3"),
    ".geotiff": ("gis", "image/tiff"),
    # NOTE: bare .tif/.tiff is ambiguous (photo scan vs GeoTIFF). It is NOT
    # mapped on purpose — the ingest must say --media-type for it.
}


class ClassificationError(ValueError):
    pass


def classify(extension: str, override: Optional[str] = None) -> Tuple[str, str, str]:
    """Return (media_type, mime, normalized_ext) for a file extension.

    `override` forces the class (still validated against MEDIA_TYPES) —
    required for unmapped extensions, allowed for mapped ones.
    """
    ext = extension.lower()
    if ext and not ext.startswith("."):
        ext = "." + ext

    if override is not None:
        if override not in MEDIA_TYPES:
            raise ClassificationError(
                f"unknown media type '{override}'; allowed: {MEDIA_TYPES}")
        mime = _EXT_MAP.get(ext, (None, "application/octet-stream"))[1]
        return override, mime, ext

    if ext not in _EXT_MAP:
        raise ClassificationError(
            f"extension '{ext}' is not in the taxonomy map — pass an explicit "
            f"media type (one of {MEDIA_TYPES}) rather than letting the gate guess")
    media_type, mime = _EXT_MAP[ext]
    return media_type, mime, ext
