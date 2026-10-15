#!/bin/sh
# Replace every "changeme" in .env with a random value (the token must be a UUIDv4,
# the encryption key 32 random bytes in base64).
set -eu
cd "$(dirname "$0")"
[ -f .env ] || cp .env.example .env
uuid() { python3 -c 'import uuid; print(uuid.uuid4())'; }
sed -i '' \
  -e "s|^OPENCTI_ADMIN_PASSWORD=changeme$|OPENCTI_ADMIN_PASSWORD=$(openssl rand -hex 16)|" \
  -e "s|^OPENCTI_ADMIN_TOKEN=changeme$|OPENCTI_ADMIN_TOKEN=$(uuid)|" \
  -e "s|^OPENCTI_ENCRYPTION_KEY=changeme$|OPENCTI_ENCRYPTION_KEY=$(openssl rand -base64 32)|" \
  -e "s|^OPENCTI_HEALTHCHECK_ACCESS_KEY=changeme$|OPENCTI_HEALTHCHECK_ACCESS_KEY=$(openssl rand -hex 16)|" \
  -e "s|^MINIO_ROOT_PASSWORD=changeme$|MINIO_ROOT_PASSWORD=$(openssl rand -hex 16)|" \
  -e "s|^RABBITMQ_DEFAULT_PASS=changeme$|RABBITMQ_DEFAULT_PASS=$(openssl rand -hex 16)|" \
  .env
grep -q "=changeme$" .env && { echo "some values are still changeme" >&2; exit 1; } || echo ".env ready"
