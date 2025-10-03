#!/usr/bin/env bash
# Helper script to execute threat hunting SQL queries against a PostgreSQL instance.
# Update the connection placeholders below before running, or export matching environment variables.

set -euo pipefail

PGHOST="${PGHOST:-<HOST>}"
PGPORT="${PGPORT:-5432}"
PGUSER="${PGUSER:-<USER>}"
PGDATABASE="${PGDATABASE:-<DATABASE>}"
PGPASSWORD="${PGPASSWORD:-<PASSWORD>}"
export PGPASSWORD

if [[ "$PGHOST" == "<HOST>" || "$PGUSER" == "<USER>" || "$PGDATABASE" == "<DATABASE>" || "$PGPASSWORD" == "<PASSWORD>" ]]; then
  cat <<MSG
[!] Please edit examples/run-queries.sh to set PGHOST, PGUSER, PGDATABASE, and PGPASSWORD (or export these variables) before running.
    Example:
      export PGHOST="localhost"
      export PGUSER="hunter"
      export PGDATABASE="threatdb"
      export PGPASSWORD="hunterpass"
      bash examples/run-queries.sh
MSG
  exit 1
fi

SQL_FILES=(
  "login-anomalies/failed-login-detection.sql"
  "login-anomalies/new-location-login.sql"
  "data-access-patterns/unusual-data-volume.sql"
  "data-access-patterns/off-hours-access.sql"
  "privilege-escalation/permission-changes.sql"
)

for sql_file in "${SQL_FILES[@]}"; do
  echo "[+] Running ${sql_file}"
  psql "host=${PGHOST} port=${PGPORT} user=${PGUSER} dbname=${PGDATABASE}" -f "${sql_file}"
  echo
done

echo "[✓] Completed executing threat hunting queries. Review the output above for findings."
