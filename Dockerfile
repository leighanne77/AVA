# AVA query gate — the workload that runs inside Confidential Space.
#
# RELEASE DISCIPLINE: before any enclave deployment,
#   1. pin the base image by digest (python:3.12-slim@sha256:...),
#   2. build, then record THIS image's digest,
#   3. sign it with cosign,
#   4. put that digest in the KMS release policy (scripts/gcp/04_*.sh).
# The digest in the release policy is what makes the seal mean something.

FROM python:3.12-slim

# no shell surprises, no bytecode litter, immediate logs
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    AVA_MODE=local \
    AVA_DATA_DIR=/var/ava/data \
    AVA_KEYS_DIR=/var/ava/keys

WORKDIR /srv/ava

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ ./app/

# non-root, own writable state dir only
RUN useradd --system --no-create-home ava \
    && mkdir -p /var/ava/data /var/ava/keys \
    && chown -R ava:ava /var/ava
USER ava

EXPOSE 8080
CMD ["uvicorn", "app.main:create_app", "--factory", "--host", "0.0.0.0", "--port", "8080"]
