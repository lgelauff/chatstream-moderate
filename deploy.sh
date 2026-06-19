#!/usr/bin/env bash
# Deploy script for chatstream-moderate on Toolforge.
# Run from anywhere on the bastion: bash ~/chatstream-moderate/deploy.sh [branch]
#
# Examples:
#   bash ~/chatstream-moderate/deploy.sh              # deploy main
#   bash ~/chatstream-moderate/deploy.sh my-branch    # deploy a specific branch

set -euo pipefail

BRANCH="${1:-main}"

echo "==> Pulling branch: $BRANCH"
cd ~/chatstream-moderate
git fetch origin
git checkout "$BRANCH"
git pull origin "$BRANCH"

# Toolforge injects the DB_* envvars into the webservice POD, not into this
# bastion shell. Without them, `flask db upgrade` here would run against a
# throwaway local SQLite file instead of ToolsDB (and, with the fail-loud guard
# in app.py, would abort outright). Read the canonical ToolsDB login from
# replica.my.cnf so migrations run against the real database.
echo "==> Loading ToolsDB credentials from replica.my.cnf..."
creds="$(~/www/python/venv/bin/python - <<'PY'
import configparser, os
c = configparser.ConfigParser()
c.read(os.path.expanduser("~/replica.my.cnf"))
print(c.get("client", "user").strip().strip("'\""))
print(c.get("client", "password").strip().strip("'\""))
PY
)"
DB_USER="$(printf '%s\n' "$creds" | sed -n 1p)"
DB_PASSWORD="$(printf '%s\n' "$creds" | sed -n 2p)"
export DB_USER DB_PASSWORD
export DB_HOST="${DB_HOST:-tools.db.svc.wikimedia.cloud}"
export DB_NAME="${DB_NAME:-${DB_USER}__chatstream}"

if [[ -z "$DB_USER" || -z "$DB_PASSWORD" ]]; then
    echo "ERROR: could not read user/password from ~/replica.my.cnf" >&2
    exit 1
fi
echo "    Target database: ${DB_NAME} @ ${DB_HOST}"

echo "==> Applying database migrations (ToolsDB)..."
FLASK_APP=app.py ~/www/python/venv/bin/python -m flask db upgrade

echo "==> Restarting web service..."
cd ~
toolforge webservice --backend=kubernetes python3.13 restart

echo "==> Done. Deployed branch: $BRANCH"
