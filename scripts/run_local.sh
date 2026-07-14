#!/usr/bin/env bash
# Run the AVA query gate locally (dev mode, mock key release).
set -euo pipefail
cd "$(dirname "$0")/.."
exec .venv/bin/uvicorn "app.main:create_app" --factory --host 127.0.0.1 --port 8080
