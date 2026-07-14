"""The AVA query gate — the only door to the vault.

Endpoints:
  GET  /healthz      liveness + mode
  GET  /attestation  what proves this gate's identity (real token in enclave mode)
  POST /query        authorized queries only; Bearer key; every call audited

There is deliberately NO endpoint that returns records. Key issuance and
revocation are owner-side CLI operations (scripts/), not network endpoints.
"""
from typing import Optional

from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

from . import __version__
from datetime import datetime, timezone

from .auditlog import AuditLog, public_key_fingerprint
from .blobvault import BlobVault
from .config import Settings
from .consumers import ConsumerRegistry
from .grants import GrantError, GrantRegistry
from .keyrelease import make_key_release
from .media import MEDIA_TYPES
from .previews import make_preview
from .queries import ALLOWED_TYPES, QueryError, run_media_query, run_query
from .tracemark import load_or_create_key
from .vault import Vault


class QueryRequest(BaseModel):
    type: str = Field(description=f"one of {ALLOWED_TYPES}")
    target: str = Field(default="records", description="'records' or 'media'")
    media_type: Optional[str] = Field(default=None, description=f"media only; one of {MEDIA_TYPES}")
    category: Optional[str] = None
    zone: Optional[str] = None
    ts_from: Optional[str] = Field(default=None, description="ISO timestamp lower bound")
    ts_to: Optional[str] = Field(default=None, description="ISO timestamp upper bound")


class QueryResponse(BaseModel):
    # The complete, closed set of what a consumer can ever receive.
    answer: dict
    query_id: int
    computed_at: str
    audit_entry_hash: str
    gate_version: str


class PreviewRequest(BaseModel):
    grant_id: str
    limit: int = Field(default=3, ge=1, le=5,
                       description="max previews per call (hard cap 5)")


class PreviewResponse(BaseModel):
    # Mode C egress: degraded, watermarked previews — nothing else.
    previews: list
    matched_total: int
    query_id: int
    computed_at: str
    audit_entry_hash: str
    gate_version: str


def create_app(settings: Optional[Settings] = None) -> FastAPI:
    settings = settings or Settings.from_env()
    settings.ensure_dirs()

    key_release = make_key_release(settings)
    vault = Vault(settings.vault_dir, key_release)
    blobvault = BlobVault(settings.vault_dir, key_release)
    registry = ConsumerRegistry(settings.registry_path)
    grants = GrantRegistry(settings.grants_path)
    audit = AuditLog(settings.audit_path, settings.keys_dir)
    # Public half of the audit signing key (AuditLog just ensured it exists).
    # Served on /attestation so a consumer can check it against the copy the
    # owner handed them out-of-band — same-key ⇒ same gate identity.
    audit_pub_pem = (settings.keys_dir / "audit_signing.pub").read_text()
    audit_pub_sha256 = public_key_fingerprint(audit_pub_pem.encode())
    # watermark master key: seeds the invisible per-consumer tracing mark
    # on every image preview (leak attribution — the tracemark layer)
    trace_key = load_or_create_key(settings.keys_dir)

    app = FastAPI(title="AVA query gate", version=__version__,
                  docs_url=None, redoc_url=None)  # no interactive docs surface

    def require_consumer(authorization: Optional[str] = Header(default=None)) -> dict:
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="missing bearer key")
        ident = registry.authenticate(authorization[len("Bearer "):])
        if ident is None:
            raise HTTPException(status_code=401, detail="unknown key")
        if ident["status"] != "active":
            raise HTTPException(status_code=403, detail="key revoked")
        return ident

    @app.get("/healthz")
    def healthz():
        return {"status": "ok", "mode": settings.mode, "version": __version__}

    @app.get("/attestation")
    def attestation():
        if settings.mode == "enclave":
            # Enclave slice: return the Confidential Space attestation token
            # (fetched from the TEE's token endpoint) so consumers can verify
            # image digest + hardware before trusting answers.
            raise HTTPException(status_code=501, detail="attestation wiring lands with the GCP slice")
        return {
            "mode": "local-dev",
            "attestation": None,
            "key_release": key_release.describe(),
            "audit_pub_pem": audit_pub_pem,
            "audit_pub_sha256": audit_pub_sha256,
            "note": "In enclave mode this returns the Confidential Space "
                    "attestation token binding this gate to its image digest.",
        }

    @app.post("/query", response_model=QueryResponse)
    def query(req: QueryRequest, ident: dict = Depends(require_consumer)):
        consumer_id = ident["consumer_id"]
        if req.type == "attest" and not ident["trusted"]:
            # commitments confirm dataset size/shape over time — an
            # owner-granted privilege, not a default
            raise HTTPException(status_code=403,
                                detail="attest requires trusted status — "
                                       "granted by the owner, per consumer")
        if req.target not in ("records", "media"):
            raise HTTPException(status_code=400, detail="target must be 'records' or 'media'")
        if req.target == "records" and req.media_type is not None:
            raise HTTPException(status_code=400, detail="media_type filter requires target 'media'")
        if req.media_type is not None and req.media_type not in MEDIA_TYPES:
            raise HTTPException(status_code=400, detail=f"media_type must be one of {MEDIA_TYPES}")
        try:
            if req.target == "media":
                answer = run_media_query(blobvault.iter_index(), req.type,
                                         media_type=req.media_type,
                                         category=req.category, zone=req.zone,
                                         ts_from=req.ts_from, ts_to=req.ts_to)
            else:
                answer = run_query(vault.iter_records(), req.type,
                                   category=req.category, zone=req.zone,
                                   ts_from=req.ts_from, ts_to=req.ts_to)
        except QueryError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        entry = audit.append(consumer_id, req.model_dump(), answer)
        return QueryResponse(
            answer=answer,
            query_id=entry["seq"],
            computed_at=entry["ts"],
            audit_entry_hash=entry["entry_hash"],
            gate_version=__version__,
        )

    @app.post("/preview", response_model=PreviewResponse)
    def preview(req: PreviewRequest, ident: dict = Depends(require_consumer)):
        """Mode C: degraded, watermarked previews under a live grant only."""
        consumer_id = ident["consumer_id"]
        try:
            grant = grants.check(req.grant_id, consumer_id)
        except GrantError as exc:
            if exc.reason == "unknown":
                raise HTTPException(status_code=404, detail="unknown grant")
            raise HTTPException(status_code=403, detail=f"grant {exc.reason}")

        f = grant["filters"]

        def in_scope(entry: dict) -> bool:
            if f.get("media_type") and entry["media_type"] != f["media_type"]:
                return False
            if f.get("zone") and entry["zone"] != f["zone"]:
                return False
            if f.get("category") and entry["category"] != f["category"]:
                return False
            ts = entry.get("captured_at")
            if (f.get("ts_from") or f.get("ts_to")) and ts is None:
                return False
            if f.get("ts_from") and ts < f["ts_from"]:
                return False
            if f.get("ts_to") and ts > f["ts_to"]:
                return False
            return True

        matched = sorted((e for e in blobvault.iter_index() if in_scope(e)),
                         key=lambda e: (e.get("captured_at") or "", e["object_id"]))
        served = matched[:req.limit]

        now = datetime.now(timezone.utc).isoformat()
        watermark = {"consumer_id": consumer_id, "grant_id": req.grant_id,
                     "generated_at": now}
        previews = [make_preview(e, blobvault.open_object(e["object_id"]),
                                 watermark, trace_key=trace_key)
                    for e in served]

        # the audit records EXACTLY what left, for whom — object ids included
        # (they appear in the owner-side log, never in the response)
        entry = audit.append(consumer_id, {
            "endpoint": "preview",
            "grant_id": req.grant_id,
            "filters": f,
            "served_object_ids": [e["object_id"] for e in served],
        }, {"served": len(previews), "matched_total": len(matched),
            "kinds": sorted({p["kind"] for p in previews})})

        return PreviewResponse(
            previews=previews,
            matched_total=len(matched),
            query_id=entry["seq"],
            computed_at=entry["ts"],
            audit_entry_hash=entry["entry_hash"],
            gate_version=__version__,
        )

    # exposed for scripts/tests, not part of the HTTP surface
    app.state.vault = vault
    app.state.blobvault = blobvault
    app.state.registry = registry
    app.state.grants = grants
    app.state.settings = settings
    return app


# Run with:  uvicorn "app.main:create_app" --factory
#            (factory mode: the app is only built when the server starts)
