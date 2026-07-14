#!/usr/bin/env bash
# Build the gate image, push to Artifact Registry, record the digest.
# The digest this prints is what 04 pins in the release policy and what
# consumers verify in the attestation token. Sign it with cosign.
set -euo pipefail
source "$(dirname "$0")/00_variables.sh"

gcloud artifacts repositories create "${REPO}" \
  --repository-format docker --location "${REGION}" \
  --project "${AVA_PROJECT_ID}" || echo "repo exists"

gcloud auth configure-docker "${REGION}-docker.pkg.dev" --quiet

IMAGE_URI="${REGION}-docker.pkg.dev/${AVA_PROJECT_ID}/${REPO}/${IMAGE}:v1"

# build for the Confidential Space host architecture
docker build --platform linux/amd64 -t "${IMAGE_URI}" "$(dirname "$0")/../.."
docker push "${IMAGE_URI}"

DIGEST=$(gcloud artifacts docker images describe "${IMAGE_URI}" \
  --format="value(image_summary.digest)")

echo
echo "Pushed: ${IMAGE_URI}"
echo "DIGEST: ${DIGEST}"
echo
echo "Next steps:"
echo "  1. Sign it:            cosign sign ${IMAGE_URI}@${DIGEST}"
echo "  2. Pin the policy:     export AVA_IMAGE_DIGEST=${DIGEST} && ./04_workload_identity.sh"
echo "  3. Launch the enclave: ./06_confidential_space.sh"
