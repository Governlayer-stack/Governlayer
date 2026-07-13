# Database Restore Verification Runbook

**Frequency:** monthly, plus before every quarterly board meeting.

A backup you have not tested is a backup you do not have.

## What this runbook validates

1. Railway's automatic Postgres backups can be dumped fresh.
2. The dump restores into a clean scratch Postgres without errors.
3. The core tables (`audit_records`, `organizations`, `users`, `risk_scores`) are present after restore.
4. The hash-chained ledger's chain is intact — no records missing `previous_hash`.

If all four pass, the restore is verified. If any fail, we have a **P0 incident** — stop deploys, escalate, and either fix the backup pipeline or move Postgres.

## Prerequisites (one-time)

- Docker installed and running (`docker ps` succeeds).
- `pg_dump` and `psql` version 15+ available (macOS: `brew install libpq && brew link --force libpq`).
- Railway CLI installed and authenticated (`railway login`).

## Procedure

```bash
# 1. Pull the current production DATABASE_URL from Railway (never commit this).
DATABASE_URL_SOURCE="$(railway variables get DATABASE_URL --service Postgres)"

# 2. Run the verifier — it will dump, spin up a scratch container, restore,
#    smoke-check, and clean up on exit.
DATABASE_URL_SOURCE="$DATABASE_URL_SOURCE" \
  ./scripts/verify_pg_restore.sh
```

The script prints a green **RESTORE VERIFIED** banner on success. Any failure exits non-zero with the failed step highlighted.

## Interpreting failures

| Failure | Meaning | Action |
|---|---|---|
| `pg_dump` errored | Cannot read from production DB | Check DATABASE_URL, permissions, network |
| Scratch Postgres never came up | Docker or port issue | Check `docker ps`, `docker logs $CONTAINER` |
| `pg_restore reported errors` | Backup is corrupt or schema-incompatible | **P0.** Do not close the loop until root-caused. |
| Table missing after restore | Schema drift between backup and current | Check Alembic migration history |
| `X ledger records missing previous_hash` | Ledger corruption during backup/restore | **P0.** Chain proof is a customer-facing promise. |

## Where the log of these runs lives

Copy the terminal transcript into a monthly note in the compliance calendar
(`/compliance-calendar` view) with fields: `date`, `runner`, `backup_size`,
`row_counts`, `pass/fail`. This becomes evidence for SOC 2 CC 6.5
(availability and processing integrity) and BC-3 (backup restoration testing).

## Escalation on failure

1. Notify `founders@governlayer.ai`.
2. Freeze production deploys until restore is re-verified against a new backup.
3. If the failure is Railway-side, open a Railway support ticket citing the
   backup timestamp and error output. In the meantime, run a manual
   `pg_dump` and store it in an encrypted S3 bucket as a stopgap.
4. If the failure is ledger-integrity, treat as a security incident:
   preserve the corrupt backup, take a fresh snapshot, and open an incident
   record via `POST /incidents`.
