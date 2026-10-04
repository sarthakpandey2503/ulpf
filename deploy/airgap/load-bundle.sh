#!/usr/bin/env bash
# Load images that save-bundle.sh produced. No registry access required.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
DIR="$ROOT/deploy/airgap/bundle"
docker load -i "$DIR/ulpf-0.1.0.tar"
if [ -f "$DIR/ulpf-deps.tar" ]; then
  docker load -i "$DIR/ulpf-deps.tar"
fi
echo "Images loaded. Create secrets with ./deploy/make-secrets.sh, then:"
echo "  docker compose -f deploy/docker-compose.yml up ulpf"
