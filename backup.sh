#!/bin/sh
# Daily database backup for the Docker setup. Keeps the last 30 days.
# Install:  chmod +x deploy/backup.sh
#           crontab -e   and add:   30 1 * * * /opt/gopin-erp/deploy/backup.sh >> /opt/gopin-erp/backups/backup.log 2>&1
set -e
cd "$(dirname "$0")/.."
. ./.env
mkdir -p backups
FILE="backups/gopin_erp_$(date +%Y-%m-%d_%H%M).sql.gz"
docker compose exec -T db pg_dump -U "$POSTGRES_USER" "$POSTGRES_DB" | gzip > "$FILE"
find backups -name 'gopin_erp_*.sql.gz' -mtime +30 -delete
echo "$(date) backup saved to $FILE"
