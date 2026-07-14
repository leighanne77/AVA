#!/usr/bin/env bash
# AVA GCP configuration — sourced by every other script in this directory.
#
# SAFETY: AVA gets its OWN GCP project. There is no default on purpose:
# you must export AVA_PROJECT_ID explicitly, and known non-AVA projects
# are refused outright.

set -euo pipefail

: "${AVA_PROJECT_ID:?Set AVA_PROJECT_ID explicitly — AVA gets its own GCP project}"

# hard refusal list: projects that must never receive AVA resources
# add the IDs of YOUR other (non-AVA) projects here so a mistyped env
# var can never land AVA resources in them
DENYLIST=("example-shared-project")
for deny in "${DENYLIST[@]}"; do
  if [[ "${AVA_PROJECT_ID}" == "${deny}" ]]; then
    echo "REFUSING: '${deny}' is not an AVA project. Create a dedicated project." >&2
    exit 1
  fi
done

export REGION="${AVA_REGION:-us-central1}"
export ZONE="${AVA_ZONE:-us-central1-a}"

# resource names — keep stable; the release policy references them
export KEYRING="ava-keyring"
export KEY="ava-vault-kek"
export BUCKET="${AVA_PROJECT_ID}-ava-vault"
export REPO="ava-repo"
export IMAGE="ava-gate"
export WORKLOAD_SA="ava-workload-sa"
export POOL="ava-pool"
export PROVIDER="ava-attestation"

# the pinned workload digest — set after building + signing the image (step 05)
export IMAGE_DIGEST="${AVA_IMAGE_DIGEST:-}"

echo "AVA target: project=${AVA_PROJECT_ID} region=${REGION} zone=${ZONE}"
