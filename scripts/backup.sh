#!/usr/bin/env bash
# Back up PostgreSQL and the evidence/report volume.
# Usage: ./scripts/backup.sh [output-directory]
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
OUT_DIR="${1:-$ROOT/backups}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
TARGET="$OUT_DIR/$STAMP"
mkdir -p "$TARGET"

if [[ ! -f .env ]]; then
  echo "error: .env not found" >&2
  exit 1
fi
set -a
# shellcheck disable=SC1091
source .env
set +a

COMPOSE=(docker compose -f docker-compose.yml)
if [[ "${PRODUCTION:-false}" == "true" ]]; then
  COMPOSE+=(-f docker-compose.prod.yml)
fi

echo "Dumping PostgreSQL…"
"${COMPOSE[@]}" exec -T postgres pg_dump -U "${POSTGRES_USER:-kingmalhare}" -d "${POSTGRES_DB:-kingmalhare}" -Fc > "$TARGET/database.dump"

echo "Archiving evidence and reports…"
"${COMPOSE[@]}" exec -T api tar -czf - -C /data storage > "$TARGET/storage.tar.gz"

sha256sum "$TARGET/database.dump" "$TARGET/storage.tar.gz" > "$TARGET/SHA256SUMS"

if command -v age >/dev/null 2>&1 && [[ -n "${BACKUP_AGE_RECIPIENT:-}" ]]; then
  echo "Encrypting a copy with age…"
  tar -czf - -C "$OUT_DIR" "$STAMP" | age -r "$BACKUP_AGE_RECIPIENT" -o "$OUT_DIR/$STAMP.tar.gz.age"
  echo "Encrypted copy: $OUT_DIR/$STAMP.tar.gz.age"
fi

echo "Backup complete: $TARGET"
echo "Store it off-host and encrypted. The .env file contains secrets and is intentionally not included."
