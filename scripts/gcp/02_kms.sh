#!/usr/bin/env bash
# Create the owner's key: keyring + KEK in Cloud KMS.
# NOTE: who runs this script matters — the account creating the key is the
# owner-side administrator. No workload, and no Google admin, gets decrypt
# rights here; that grant happens ONLY in 04, gated on attestation.
set -euo pipefail
source "$(dirname "$0")/00_variables.sh"

gcloud kms keyrings create "${KEYRING}" \
  --location "${REGION}" --project "${AVA_PROJECT_ID}" || echo "keyring exists"

gcloud kms keys create "${KEY}" \
  --keyring "${KEYRING}" --location "${REGION}" \
  --purpose encryption \
  --protection-level software \
  --project "${AVA_PROJECT_ID}" || echo "key exists"

echo "KEK ready: projects/${AVA_PROJECT_ID}/locations/${REGION}/keyRings/${KEYRING}/cryptoKeys/${KEY}"
echo "Export for the gate:  AVA_KMS_KEY_NAME=projects/${AVA_PROJECT_ID}/locations/${REGION}/keyRings/${KEYRING}/cryptoKeys/${KEY}"
