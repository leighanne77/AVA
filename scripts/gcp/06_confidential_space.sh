#!/usr/bin/env bash
# Launch the sealed VM: Confidential Space running the pinned gate image.
#
# PRODUCTION uses --image-family=confidential-space (no SSH, no debug —
# the no-peek guarantee). For first bring-up you may launch the debug
# variant, but the release policy's STABLE condition (04) means the KEK
# will NOT be released to a debug image: dry-run with synthetic data only.
set -euo pipefail
source "$(dirname "$0")/00_variables.sh"

: "${IMAGE_DIGEST:?Set AVA_IMAGE_DIGEST (sha256:...) so the VM runs the pinned image}"

IMAGE_URI="${REGION}-docker.pkg.dev/${AVA_PROJECT_ID}/${REPO}/${IMAGE}@${IMAGE_DIGEST}"
IMAGE_FAMILY="${AVA_CS_IMAGE_FAMILY:-confidential-space}"   # or confidential-space-debug

gcloud compute instances create ava-gate-v1 \
  --project "${AVA_PROJECT_ID}" --zone "${ZONE}" \
  --machine-type n2d-standard-2 \
  --confidential-compute-type SEV_SNP \
  --maintenance-policy TERMINATE \
  --shielded-secure-boot \
  --image-project confidential-space-images \
  --image-family "${IMAGE_FAMILY}" \
  --service-account "${WORKLOAD_SA}@${AVA_PROJECT_ID}.iam.gserviceaccount.com" \
  --scopes cloud-platform \
  --metadata "^~^tee-image-reference=${IMAGE_URI}~tee-container-log-redirect=true~tee-env-AVA_MODE=enclave~tee-env-AVA_KMS_KEY_NAME=projects/${AVA_PROJECT_ID}/locations/${REGION}/keyRings/${KEYRING}/cryptoKeys/${KEY}"

echo "Sealed VM launching. The gate serves on :8080; front it with an HTTPS load balancer before any consumer touches it."
