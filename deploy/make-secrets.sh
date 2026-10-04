#!/usr/bin/env bash
# Generate deployment secrets locally (works offline). Never commit deploy/secrets/.
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p secrets && chmod 700 secrets
rand() { head -c 32 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 32; }

[ -f secrets/clickhouse_password ] || rand > secrets/clickhouse_password
[ -f secrets/minio_user ] || echo "ulpf-admin" > secrets/minio_user
[ -f secrets/minio_password ] || rand > secrets/minio_password

if [ ! -f secrets/ulpf_tokens.json ]; then
  ADMIN=$(rand); ANALYST=$(rand); VIEWER=$(rand); INGEST=$(rand)
  python3 - "$ADMIN" "$ANALYST" "$VIEWER" "$INGEST" > secrets/ulpf_tokens.json <<'PY'
import hashlib, json, sys
roles = ["admin", "analyst", "viewer", "ingest"]
print(json.dumps({"tokens": [{"name": r, "role": r, "sha256": hashlib.sha256(t.encode()).hexdigest()}
                             for r, t in zip(roles, sys.argv[1:])]}, indent=2))
PY
  echo "API tokens (store them now, only hashes are kept):"
  echo "  admin=$ADMIN"; echo "  analyst=$ANALYST"; echo "  viewer=$VIEWER"; echo "  ingest=$INGEST"
fi

if [ ! -f secrets/ca.crt ]; then
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 825 \
    -subj "/CN=ULPF Local CA" -keyout secrets/ca.key -out secrets/ca.crt 2>/dev/null
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
    -subj "/CN=ulpf-syslog" -keyout secrets/syslog.key -out secrets/syslog.csr 2>/dev/null
  openssl x509 -req -in secrets/syslog.csr -CA secrets/ca.crt -CAkey secrets/ca.key -CAcreateserial \
    -days 825 -out secrets/syslog.crt 2>/dev/null
  rm -f secrets/syslog.csr
fi
chmod 600 secrets/*
echo "Secrets ready in deploy/secrets/"
