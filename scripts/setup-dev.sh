#!/usr/bin/env bash
# scripts/setup-dev.sh — Idempotent dev environment bootstrap
# Starts Postgres, waits for health, applies migrations, runs a smoke check.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

DB_HOST="${ADMISSION_DB_HOST:-localhost}"
DB_PORT="${ADMISSION_DB_PORT:-12432}"
DB_NAME="${ADMISSION_DB_NAME:-admission}"
DB_USER="${ADMISSION_DB_USER:-admission}"
DB_PASS="${ADMISSION_DB_PASS:-admission_dev}"

DB_DSN="postgresql://${DB_USER}:${DB_PASS}@${DB_HOST}:${DB_PORT}/${DB_NAME}"

echo "==> Starting docker-compose services..."
docker compose -f "$PROJECT_ROOT/docker-compose.yml" up -d

echo "==> Waiting for Postgres health check..."
MAX_WAIT=60
ELAPSED=0
until docker compose -f "$PROJECT_ROOT/docker-compose.yml" exec -T postgres pg_isready -U "$DB_USER" -d "$DB_NAME" > /dev/null 2>&1; do
    if [ "$ELAPSED" -ge "$MAX_WAIT" ]; then
        echo "ERROR: Postgres did not become ready within ${MAX_WAIT}s"
        exit 1
    fi
    sleep 2
    ELAPSED=$((ELAPSED + 2))
    echo "    ...waiting (${ELAPSED}s)"
done
echo "    Postgres is ready (${ELAPSED}s)"

echo "==> Applying migrations..."
for migration in "$PROJECT_ROOT"/migrations/*.sql; do
    if [ -f "$migration" ]; then
        echo "    Applying $(basename "$migration")..."
        psql "$DB_DSN" -f "$migration"
    fi
done

echo "==> Running health check query..."
RESULT=$(psql "$DB_DSN" -t -c "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = 'public' AND table_type = 'BASE TABLE';")
TABLE_COUNT=$(echo "$RESULT" | tr -d '[:space:]')
echo "    Found $TABLE_COUNT tables in public schema"

if [ "$TABLE_COUNT" -lt 5 ]; then
    echo "ERROR: Expected at least 5 tables, found $TABLE_COUNT"
    exit 1
fi

echo "==> Dev environment ready!"
echo "    DSN: $DB_DSN"
