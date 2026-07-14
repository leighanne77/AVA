"""Authorized queries — the ONLY way information leaves the vault.

Answers, not archives: every query type returns an aggregate or a boolean.
No query type can return a record, a field value from a single record, or
any list of records. Adding a query type is a security decision, not a
feature request.
"""
from typing import Dict, Iterator, Optional

from .merkle import merkle_root_hex

ALLOWED_TYPES = ("count", "exists", "sum", "mean")
# media additionally supports 'attest': a Merkle commitment to the matched
# set — lets the owner later prove any single object's membership offline.
MEDIA_ALLOWED_TYPES = ALLOWED_TYPES + ("attest",)


class QueryError(ValueError):
    pass


def _matches(rec: Dict, category: Optional[str], zone: Optional[str],
             ts_from: Optional[str], ts_to: Optional[str]) -> bool:
    if category is not None and rec.get("category") != category:
        return False
    if zone is not None and rec.get("zone") != zone:
        return False
    ts = rec.get("ts", "")
    if ts_from is not None and ts < ts_from:
        return False
    if ts_to is not None and ts > ts_to:
        return False
    return True


def _aggregate(items: Iterator[Dict], qtype: str, value_of) -> Dict:
    matched = 0
    total = 0.0
    for item in items:
        matched += 1
        total += value_of(item)
        if qtype == "exists":
            # short-circuit: existence established, stop decrypting
            return {"type": "exists", "result": True}

    if qtype == "exists":
        return {"type": "exists", "result": False}
    if qtype == "count":
        return {"type": "count", "result": matched}
    if qtype == "sum":
        return {"type": "sum", "result": round(total, 6), "matched": matched}
    # mean
    if matched == 0:
        return {"type": "mean", "result": None, "matched": 0}
    return {"type": "mean", "result": round(total / matched, 6), "matched": matched}


def run_query(records: Iterator[Dict], qtype: str,
              category: Optional[str] = None, zone: Optional[str] = None,
              ts_from: Optional[str] = None, ts_to: Optional[str] = None) -> Dict:
    """Compute one authorized answer over decrypted records (in memory only)."""
    if qtype not in ALLOWED_TYPES:
        raise QueryError(f"query type '{qtype}' not allowed; allowed: {ALLOWED_TYPES}")
    matching = (r for r in records if _matches(r, category, zone, ts_from, ts_to))
    return _aggregate(matching, qtype, lambda r: float(r.get("value", 0.0)))


def run_media_query(index: Iterator[Dict], qtype: str,
                    media_type: Optional[str] = None,
                    category: Optional[str] = None, zone: Optional[str] = None,
                    ts_from: Optional[str] = None, ts_to: Optional[str] = None) -> Dict:
    """Answers over the media INDEX — never the payloads.

    Time filters apply to `captured_at`; sum/mean aggregate `size_bytes`
    (dataset shape, same disclosure class as count). Nothing that could
    identify an object — id, hash, extension — enters the answer.
    """
    if qtype not in MEDIA_ALLOWED_TYPES:
        raise QueryError(f"query type '{qtype}' not allowed; allowed: {MEDIA_ALLOWED_TYPES}")

    def match(entry: Dict) -> bool:
        if media_type is not None and entry.get("media_type") != media_type:
            return False
        ts = entry.get("captured_at")
        if ts is None and (ts_from is not None or ts_to is not None):
            return False  # unknown capture time never matches a time-bounded ask
        rec_view = {"category": entry.get("category"), "zone": entry.get("zone"), "ts": ts or ""}
        return _matches(rec_view, category, zone, ts_from, ts_to)

    matching = (e for e in index if match(e))
    if qtype == "attest":
        hashes = [e["sha256_plain"] for e in matching]
        # the root is the ONLY identifier-derived value that ever leaves the
        # gate, and it identifies the SET, not any object (domain-separated
        # tree: the root never equals a leaf hash)
        return {"type": "attest", "result": merkle_root_hex(hashes), "matched": len(hashes)}
    return _aggregate(matching, qtype, lambda e: float(e.get("size_bytes", 0)))
