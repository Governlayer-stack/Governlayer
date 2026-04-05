#!/usr/bin/env bash
# GovernLayer Database Backup Script
#
# Reads DATABASE_URL from environment (or .env file).
# Creates timestamped, gzip-compressed pg_dump backups.
# Deletes backups older than 30 days.
#
# Usage:
#   export DATABASE_URL="postgresql://user:pass@host:5432/governlayer"
#   ./scripts/backup.sh
#
# Or with a .env file in the project root:
#   ./scripts/backup.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
BACKUP_DIR="${BACKUP_DIR:-$PROJECT_ROOT/backups}"
RETENTION_DAYS="${RETENTION_DAYS:-30}"

# Load .env if DATABASE_URL is not already set
if [ -z "${DATABASE_URL:-}" ] && [ -f "$PROJECT_ROOT/.env" ]; then
    export "$(grep -E '^DATABASE_URL=' "$PROJECT_ROOT/.env" | head -1 | xargs)"
fi

if [ -z "${DATABASE_URL:-}" ]; then
    echo "ERROR: DATABASE_URL is not set. Export it or add it to .env" >&2
    exit 1
fi

# Create backup directory
mkdir -p "$BACKUP_DIR"

TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
BACKUP_FILE="$BACKUP_DIR/governlayer_${TIMESTAMP}.sql.gz"

echo "Starting backup: $BACKUP_FILE"
pg_dump "$DATABASE_URL" --no-owner --no-acl | gzip > "$BACKUP_FILE"
echo "Backup complete: $(du -h "$BACKUP_FILE" | cut -f1)"

# Delete backups older than retention period
DELETED=$(find "$BACKUP_DIR" -name "governlayer_*.sql.gz" -mtime +"$RETENTION_DAYS" -print -delete | wc -l)
if [ "$DELETED" -gt 0 ]; then
    echo "Cleaned up $DELETED backup(s) older than $RETENTION_DAYS days"
fi

echo "Done. Active backups in $BACKUP_DIR:"
ls -lh "$BACKUP_DIR"/governlayer_*.sql.gz 2>/dev/null || echo "  (none)"
