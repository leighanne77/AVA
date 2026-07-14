"""Blob vault: all five media classes ingest encrypted, round-trip, never leak."""
from pathlib import Path

import pytest

from app.blobvault import BlobVault
from app.keyrelease import KeyReleaseError, LocalMockKMS
from app.media import MEDIA_TYPES, ClassificationError, classify

# one synthetic payload per media class, each with a distinctive marker that
# must never appear on disk. Realistic magic bytes where cheap.
FIXTURES = {
    "video":        (".mp4",     b"\x00\x00\x00\x18ftypmp42SECRET-FRAMES-marker" + b"\x07" * 64),
    "audio":        (".wav",     b"RIFF\x24\x00\x00\x00WAVEfmt SECRET-SOUND-marker" + b"\x01" * 64),
    "tabular":      (".csv",     b"site,metric,reading\nSECRET-ROW-marker,42,3.14\n"),
    "unstructured": (".pdf",     b"%PDF-1.4 SECRET-DOC-marker stream endstream %%EOF"),
    "gis":          (".geojson", b'{"type":"FeatureCollection","name":"SECRET-COORDS-marker","features":[]}'),
}
MARKERS = [b"SECRET-FRAMES", b"SECRET-SOUND", b"SECRET-ROW", b"SECRET-DOC", b"SECRET-COORDS"]


@pytest.fixture()
def blobvault(settings):
    return BlobVault(settings.vault_dir, LocalMockKMS(settings.keys_dir))


@pytest.fixture()
def loaded_blobvault(blobvault):
    entries = {}
    for mt, (ext, payload) in FIXTURES.items():
        entries[mt] = blobvault.put(payload, ext, zone="zone-01", category="alpha",
                                    captured_at="2026-06-01T00:00:00+00:00")
    return blobvault, entries


def _all_disk_bytes(directory: Path) -> bytes:
    return b"".join(p.read_bytes() for p in sorted(directory.rglob("*")) if p.is_file())


# ---- taxonomy ----

def test_all_five_classes_classify():
    for mt, (ext, _) in FIXTURES.items():
        got_type, mime, got_ext = classify(ext)
        assert got_type == mt
        assert got_ext == ext
        assert mime


def test_taxonomy_is_the_agreed_closed_set():
    assert MEDIA_TYPES == ("video", "audio", "tabular", "unstructured", "gis")


def test_unknown_extension_refused_without_override():
    with pytest.raises(ClassificationError):
        classify(".xyz")


def test_ambiguous_tif_requires_explicit_class():
    # .tif could be a photo scan (unstructured) or GeoTIFF (gis) — no guessing
    with pytest.raises(ClassificationError):
        classify(".tif")
    assert classify(".tif", override="gis")[0] == "gis"
    assert classify(".tif", override="unstructured")[0] == "unstructured"


def test_override_must_be_a_real_class():
    with pytest.raises(ClassificationError):
        classify(".csv", override="hologram")


# ---- blob vault ----

def test_all_classes_roundtrip(loaded_blobvault):
    vault, entries = loaded_blobvault
    for mt, (ext, payload) in FIXTURES.items():
        assert vault.open_object(entries[mt]["object_id"]) == payload


def test_index_holds_all_classes_with_hashes(loaded_blobvault):
    vault, entries = loaded_blobvault
    index = list(vault.iter_index())
    assert sorted(e["media_type"] for e in index) == sorted(FIXTURES.keys())
    for e in index:
        assert len(e["sha256_plain"]) == 64
        assert e["size_bytes"] > 0
        assert "filename" not in e  # extensions only — filenames leak semantics


def test_no_plaintext_on_disk_any_class(settings, loaded_blobvault):
    disk = _all_disk_bytes(settings.data_dir)
    for marker in MARKERS:
        assert marker not in disk, f"payload marker {marker} leaked to disk"
    # index content (zone/category) must be encrypted too
    assert b"zone-01" not in disk and b"alpha" not in disk


def test_blob_files_are_ciphertext_not_renamed_copies(settings, loaded_blobvault):
    vault, entries = loaded_blobvault
    for mt, (ext, payload) in FIXTURES.items():
        enc = (settings.vault_dir / "media" / f"{entries[mt]['object_id']}.enc").read_bytes()
        assert payload not in enc
        assert enc[:12] != payload[:12]


def test_swapped_blob_files_fail_decryption(settings, loaded_blobvault):
    """AAD binds ciphertext to object_id: renaming one object's file over
    another must fail, not silently impersonate."""
    vault, entries = loaded_blobvault
    media = settings.vault_dir / "media"
    a = media / f"{entries['video']['object_id']}.enc"
    b = media / f"{entries['audio']['object_id']}.enc"
    a_bytes, b_bytes = a.read_bytes(), b.read_bytes()
    a.write_bytes(b_bytes), b.write_bytes(a_bytes)
    with pytest.raises(Exception):
        vault.open_object(entries["video"]["object_id"])


def test_wrong_key_cannot_open_blobvault(settings, loaded_blobvault, tmp_path):
    with pytest.raises(KeyReleaseError):
        BlobVault(settings.vault_dir, LocalMockKMS(tmp_path / "other-keys"))


def test_reopen_same_key_reads_index_and_blobs(settings, loaded_blobvault):
    vault, entries = loaded_blobvault
    vault2 = BlobVault(settings.vault_dir, LocalMockKMS(settings.keys_dir))
    assert len(list(vault2.iter_index())) == len(FIXTURES)
    assert vault2.open_object(entries["gis"]["object_id"]) == FIXTURES["gis"][1]
