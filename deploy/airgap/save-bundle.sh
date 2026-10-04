#!/usr/bin/env bash
# Build an offline bundle on a connected machine. Copy deploy/airgap/ to the isolated host.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
OUT="$ROOT/deploy/airgap/bundle"
WHEELS="$ROOT/deploy/airgap/wheels"
mkdir -p "$OUT" "$WHEELS"

python3 -m pip download -r "$ROOT/requirements.txt" -d "$WHEELS"

docker build -f "$ROOT/deploy/Dockerfile" \
  --build-arg PIP_ARGS="--no-index --find-links=/wheels" \
  -t ulpf:0.1.0 "$ROOT"
docker save ulpf:0.1.0 -o "$OUT/ulpf-0.1.0.tar"

# Optional full profile. Pull once here; the isolated host must not pull.
for img in \
  docker.redpanda.com/redpandadata/redpanda:v24.2.7 \
  clickhouse/clickhouse-server:24.8 \
  minio/minio:RELEASE.2024-10-13T13-34-11Z \
  ollama/ollama:0.3.14
do
  docker pull "$img"
done
docker save \
  docker.redpanda.com/redpandadata/redpanda:v24.2.7 \
  clickhouse/clickhouse-server:24.8 \
  minio/minio:RELEASE.2024-10-13T13-34-11Z \
  ollama/ollama:0.3.14 \
  -o "$OUT/ulpf-deps.tar"

echo "Bundle ready in $OUT"
echo "Also copy $WHEELS if you need to rebuild the image offline."
