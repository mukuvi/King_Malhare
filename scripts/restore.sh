#!/usr/bin/env bash
# Restore a backup produced by scripts/backup.sh.
# Usage: PRODUCTION=true ./scripts/restore.sh backups/20260101T030000Z
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
SRC="${1:-}"
if [[ -z "$SRC" || ! -d "$SRC" ]]; then
  echo "usage: $0 <backup-directory>" >&2
  exit 1
fi
if [[ ! -f "$SRC/database.dump" || ! -f "$SRC/storage.tar.gz" ]]; then
  echo "error: backup is missing database.dump or storage.tar.gz" >&2
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

echo "This will replace the current database and storage volume."
read -r -p "Type RESTORE to continue: " CONFIRM
[[ "$CONFIRM" == "RESTORE" ]] || { echo "Aborted."; exit 1; }

echo "Stopping application services…"
"${COMPOSE[@]}" stop api worker web || true
"${COMPOSE[@]}" up -d postgres redis

echo "Restoring PostgreSQL…"
"${COMPOSE[@]}" exec -T postgres pg_restore -U "${POSTGRES_USER:-kingmalhare}" -d "${POSTGRES_DB:-kingmalhare}" --clean --if-exists < "$SRC/database.dump"

echo "Restoring storage…"
"${COMPOSE[@]}" run --rm --no-deps -T api sh -c 'rm -rf /data/storage && tar -xzf - -C /data' < "$SRC/storage.tar.gz"

echo "Starting services…"
"${COMPOSE[@]}" up -d api worker web
echo "Restore complete. Verify /api/v1/ready and a report download."
