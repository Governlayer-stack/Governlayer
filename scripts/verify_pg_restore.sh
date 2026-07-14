#!/usr/bin/env bash
#
# Verify that a Postgres backup can actually be restored — end-to-end.
#
# A backup you have not tested is a backup you do not have. This script:
#   1. Takes a fresh dump of the source database (via DATABASE_URL_SOURCE).
#   2. Spins up a scratch Postgres container.
#   3. Restores the dump into the scratch container.
#   4. Runs a set of smoke queries to confirm data + schema landed.
#   5. Prints a pass/fail verdict and cleans up.
#
# Usage:
#   DATABASE_URL_SOURCE="$(railway variables get DATABASE_URL --service Postgres)" \
#     ./scripts/verify_pg_restore.sh
#
# Or for a local run against the dev Postgres:
#   DATABASE_URL_SOURCE="postgresql://localhost/governlayer" \
#     ./scripts/verify_pg_restore.sh
#
# Requires: docker, pg_dump, psql (all bundled with libpq).

set -euo pipefail

: "${DATABASE_URL_SOURCE:?DATABASE_URL_SOURCE must be set (e.g. Railway Postgres URL)}"

SCRATCH_CONTAINER="governlayer-restore-verify-$$"
SCRATCH_PORT=$(( ( RANDOM % 10000 ) + 15000 ))
SCRATCH_PASSWORD="verify-$(date +%s)"
DUMP_FILE="/tmp/governlayer-verify-$$.dump"

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

log() { printf "${YELLOW}[verify_restore]${NC} %s\n" "$1"; }
ok()  { printf "${GREEN}✓${NC} %s\n" "$1"; }
fail(){ printf "${RED}✗ %s${NC}\n" "$1" >&2; }

cleanup() {
  log "cleanup"
  docker rm -f "$SCRATCH_CONTAINER" >/dev/null 2>&1 || true
  rm -f "$DUMP_FILE" >/dev/null 2>&1 || true
}
trap cleanup EXIT

# 1. Dump
log "dumping source database to $DUMP_FILE"
pg_dump --format=custom --no-owner --no-privileges \
  --file "$DUMP_FILE" "$DATABASE_URL_SOURCE"
ok "dump succeeded ($(du -h "$DUMP_FILE" | cut -f1))"

# 2. Scratch Postgres — use a version >= the source so all reserved words /
#    parameters emitted by pg_dump are understood on restore. Railway's
#    managed Postgres tracks the latest LTS (17 at time of writing), so we
#    default to 17 unless the caller overrides with SCRATCH_PG_IMAGE.
SCRATCH_PG_IMAGE="${SCRATCH_PG_IMAGE:-postgres:17-alpine}"
log "starting scratch Postgres on :$SCRATCH_PORT (container $SCRATCH_CONTAINER, image $SCRATCH_PG_IMAGE)"
docker run -d --rm \
  --name "$SCRATCH_CONTAINER" \
  -e POSTGRES_PASSWORD="$SCRATCH_PASSWORD" \
  -e POSTGRES_DB=governlayer_restore_test \
  -p "$SCRATCH_PORT:5432" \
  "$SCRATCH_PG_IMAGE" >/dev/null

log "waiting for scratch Postgres to accept connections"
for i in {1..30}; do
  if docker exec "$SCRATCH_CONTAINER" pg_isready -U postgres >/dev/null 2>&1; then
    ok "scratch Postgres up"
    break
  fi
  sleep 1
  if [ "$i" = "30" ]; then
    fail "scratch Postgres never came up"
    exit 1
  fi
done

RESTORE_URL="postgresql://postgres:${SCRATCH_PASSWORD}@localhost:${SCRATCH_PORT}/governlayer_restore_test"

# 3. Restore
log "restoring dump into scratch"
pg_restore --no-owner --no-privileges --clean --if-exists \
  --dbname "$RESTORE_URL" "$DUMP_FILE" || {
    fail "pg_restore reported errors — see output above"
    exit 1
  }
ok "restore complete"

# 4. Smoke queries — these are the tables and invariants that matter most
log "running smoke queries"

check() {
  local desc="$1"
  local query="$2"
  local expected_min="${3:-1}"
  local actual
  actual=$(psql "$RESTORE_URL" -tAc "$query")
  if [ "$actual" -ge "$expected_min" ] 2>/dev/null; then
    ok "$desc — $actual rows (>= $expected_min)"
  else
    fail "$desc — $actual rows (expected >= $expected_min)"
    exit 1
  fi
}

check "audit_records table present"       "SELECT count(*) FROM audit_records;"       0
check "organizations table present"       "SELECT count(*) FROM organizations;"       0
check "users table present"               "SELECT count(*) FROM users;"               0
check "risk_scores table present"         "SELECT count(*) FROM risk_scores;"         0

# Ledger integrity — every non-genesis record must have a previous_hash
log "verifying ledger hash-chain integrity"
BROKEN_LINKS=$(psql "$RESTORE_URL" -tAc "
  SELECT count(*) FROM audit_records a
  WHERE a.id > (SELECT COALESCE(min(id), 0) FROM audit_records)
    AND a.previous_hash IS NULL;
")
if [ "$BROKEN_LINKS" = "0" ]; then
  ok "ledger chain intact after restore ($(psql "$RESTORE_URL" -tAc "SELECT count(*) FROM audit_records;") records)"
else
  fail "$BROKEN_LINKS ledger records missing previous_hash — chain is broken"
  exit 1
fi

echo
printf "${GREEN}════════════════════════════════════════════════════════════${NC}\n"
printf "${GREEN}  RESTORE VERIFIED — $DATABASE_URL_SOURCE is safely restorable${NC}\n"
printf "${GREEN}════════════════════════════════════════════════════════════${NC}\n"
