#!/usr/bin/env bash
# Enable the APIs AVA v1 needs.
set -euo pipefail
source "$(dirname "$0")/00_variables.sh"

gcloud services enable \
  compute.googleapis.com \
  confidentialcomputing.googleapis.com \
  cloudkms.googleapis.com \
  storage.googleapis.com \
  artifactregistry.googleapis.com \
  iamcredentials.googleapis.com \
  sts.googleapis.com \
  --project "${AVA_PROJECT_ID}"

echo "APIs enabled."
