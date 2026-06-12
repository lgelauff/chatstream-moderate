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

echo "==> Applying database migrations..."
FLASK_APP=app.py ~/www/python/venv/bin/python -m flask db upgrade

echo "==> Restarting web service..."
cd ~
toolforge webservice --backend=kubernetes python3.13 restart

echo "==> Done. Deployed branch: $BRANCH"
