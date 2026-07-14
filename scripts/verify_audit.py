#!/usr/bin/env python3
"""Verify the audit log's hash chain and signatures — anyone holding the
public key can run this; it needs no access to the vault or any secret.

Usage:  .venv/bin/python scripts/verify_audit.py
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.auditlog import verify_chain  # noqa: E402
from app.config import Settings        # noqa: E402


def main():
    settings = Settings.from_env()
    pub = (settings.keys_dir / "audit_signing.pub").read_bytes()
    ok, bad_seq = verify_chain(settings.audit_path, pub)
    if ok:
        print("audit chain VERIFIED — every entry intact and signed.")
    else:
        print(f"audit chain BROKEN at seq {bad_seq} — tampering or corruption.")
        sys.exit(1)


if __name__ == "__main__":
    main()
