#!/usr/bin/env bash
# The heart of AVA: the release policy.
#
# Creates a workload identity pool whose provider ONLY admits tokens from
# Google's Confidential Space attestation verifier, and ONLY when the
# attested workload is our exact pinned image digest running on a
# production (STABLE) Confidential Space image. That identity — and nothing
# else — gets decrypt on the KEK.
#
# Requires: IMAGE_DIGEST exported (set AVA_IMAGE_DIGEST after step 05 build).
set -euo pipefail
source "$(dirname "$0")/00_variables.sh"

: "${IMAGE_DIGEST:?Set AVA_IMAGE_DIGEST (sha256:...) — pin the exact workload first (see 05)}"

PROJECT_NUMBER=$(gcloud projects describe "${AVA_PROJECT_ID}" --format="value(projectNumber)")

# service account the Confidential Space VM runs as (no key files, ever)
gcloud iam service-accounts create "${WORKLOAD_SA}" \
  --project "${AVA_PROJECT_ID}" \
  --display-name "AVA workload SA" || echo "SA exists"

# workload identity pool + Confidential Space attestation provider
gcloud iam workload-identity-pools create "${POOL}" \
  --location global --project "${AVA_PROJECT_ID}" \
  --display-name "AVA attestation pool" || echo "pool exists"

gcloud iam workload-identity-pools providers create-oidc "${PROVIDER}" \
  --location global --project "${AVA_PROJECT_ID}" \
  --workload-identity-pool "${POOL}" \
  --issuer-uri "https://confidentialcomputing.googleapis.com/" \
  --allowed-audiences "https://sts.googleapis.com" \
  --attribute-mapping "google.subject='assertion.sub'" \
  --attribute-condition "assertion.submods.container.image_digest == '${IMAGE_DIGEST}' \
&& assertion.submods.confidential_space.support_attributes.exists(a, a == 'STABLE') \
&& '${WORKLOAD_SA}@${AVA_PROJECT_ID}.iam.gserviceaccount.com' in assertion.google_service_accounts" \
  || echo "provider exists (delete + recreate to change the pinned digest)"

MEMBER="principalSet://iam.googleapis.com/projects/${PROJECT_NUMBER}/locations/global/workloadIdentityPools/${POOL}/*"

# THE grant: decrypt only for the attested identity
gcloud kms keys add-iam-policy-binding "${KEY}" \
  --keyring "${KEYRING}" --location "${REGION}" --project "${AVA_PROJECT_ID}" \
  --member "${MEMBER}" \
  --role "roles/cloudkms.cryptoKeyEncrypterDecrypter"

# vault bucket read for the attested identity
gcloud storage buckets add-iam-policy-binding "gs://${BUCKET}" \
  --member "${MEMBER}" \
  --role "roles/storage.objectViewer"

echo "Release policy live: KEK decrypt is granted ONLY to workloads attesting digest ${IMAGE_DIGEST}."
echo "To revoke EVERYTHING at once: remove the binding or disable the key version."
