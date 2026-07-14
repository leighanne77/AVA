#!/usr/bin/env bash
# The vault bucket: ciphertext only, uniform access, no public access ever.
set -euo pipefail
source "$(dirname "$0")/00_variables.sh"

gcloud storage buckets create "gs://${BUCKET}" \
  --project "${AVA_PROJECT_ID}" \
  --location "${REGION}" \
  --uniform-bucket-level-access \
  --public-access-prevention || echo "bucket exists"

echo "Vault bucket ready: gs://${BUCKET} (holds ciphertext + wrapped DEK only)"
