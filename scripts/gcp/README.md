# AVA GCP provisioning

Run in order, from this directory, once an AVA-dedicated GCP project exists:

```bash
export AVA_PROJECT_ID=<the-ava-project>      # never a shared project; denylist enforced
./01_apis.sh
./02_kms.sh          # the owner's KEK — created by the OWNER-side admin account
./03_storage.sh      # ciphertext vault bucket
./05_build_push.sh   # build + push the gate; prints the image DIGEST
export AVA_IMAGE_DIGEST=sha256:...           # from 05's output
./04_workload_identity.sh                    # the release policy, pinned to that digest
./06_confidential_space.sh                   # launch the sealed VM
```

Order note: 05 runs before 04 because the release policy needs the digest.

## What maps to what

| Walkthrough step | Script |
|---|---|
| 1 Encrypt & store | `02_kms.sh` + `03_storage.sh` |
| 2 Pin the approved code | `05_build_push.sh` (digest) + `04_workload_identity.sh` (policy) |
| 3–5 Boot, attest, key release | `06_confidential_space.sh` + the provider condition in `04` |
| 8 Revoke at will | remove the KMS binding, or revoke one consumer key via `scripts/revoke_consumer.py` |

## Still to land in this slice (needs the real project)

- `CloudKMSKeyRelease` implementation in `app/keyrelease.py` (google-cloud-kms).
- Vault objects in the bucket instead of the local `data/vault` dir.
- `/attestation` endpoint returning the real Confidential Space token.
- HTTPS load balancer in front of the gate.
- cosign signing in CI rather than by hand.
