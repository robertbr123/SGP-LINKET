#!/bin/bash
# Entrypoint do container backup:
# 1. Gera config rclone para R2 a partir das env vars
# 2. Instala cron job na hora configurada
# 3. Mantém crond rodando em foreground

set -e

# Validação básica
if [ -z "${R2_ACCOUNT_ID:-}" ] || [ -z "${R2_ACCESS_KEY_ID:-}" ] || [ -z "${R2_SECRET_ACCESS_KEY:-}" ]; then
    echo "[entrypoint] AVISO: variáveis R2_* não configuradas — backups vão falhar até preencher."
fi

# Config rclone para Cloudflare R2 (S3-compatível)
mkdir -p /tmp
cat > /tmp/rclone.conf <<EOF
[r2]
type = s3
provider = Cloudflare
access_key_id = ${R2_ACCESS_KEY_ID:-}
secret_access_key = ${R2_SECRET_ACCESS_KEY:-}
endpoint = https://${R2_ACCOUNT_ID:-missing}.r2.cloudflarestorage.com
region = auto
acl = private
EOF
chmod 600 /tmp/rclone.conf

# Exporta env vars pro cron (que não herda environment)
ENV_FILE="/etc/cron.d/backup-env"
{
    echo "DB_HOST=${DB_HOST:-postgres}"
    echo "DB_NAME=${DB_NAME:-radius}"
    echo "DB_USER=${DB_USER:-radius}"
    echo "DB_PASS=${DB_PASS:-radiuspassword}"
    echo "MONGO_HOST=${MONGO_HOST:-mongodb}"
    echo "R2_BUCKET=${R2_BUCKET:-sgp-linket-backups}"
    echo "R2_PREFIX=${R2_PREFIX:-}"
    echo "BACKUP_RETENTION_DAYS=${BACKUP_RETENTION_DAYS:-7}"
} > "$ENV_FILE"

# Cron job — todo dia às BACKUP_HOUR (default 03:00)
BACKUP_HOUR="${BACKUP_HOUR:-3}"
BACKUP_MINUTE="${BACKUP_MINUTE:-0}"
CRON_FILE="/etc/cron.d/sgp-backup"
cat > "$CRON_FILE" <<EOF
SHELL=/bin/bash
BASH_ENV=/etc/cron.d/backup-env
${BACKUP_MINUTE} ${BACKUP_HOUR} * * * root /app/backup.sh >> /var/log/backup.log 2>&1
EOF
chmod 644 "$CRON_FILE"

# Log file pra tail
touch /var/log/backup.log

echo "[entrypoint] Backup agendado para ${BACKUP_HOUR}:$(printf '%02d' ${BACKUP_MINUTE}) diariamente"
echo "[entrypoint] Bucket R2:  ${R2_BUCKET:-sgp-linket-backups}"
if [ -n "${R2_PREFIX:-}" ]; then
    echo "[entrypoint] Prefix:      ${R2_PREFIX}/"
    echo "[entrypoint] Caminho:     ${R2_BUCKET}/${R2_PREFIX}/YYYY/MM/timestamp/"
else
    echo "[entrypoint] Caminho:     ${R2_BUCKET:-sgp-linket-backups}/YYYY/MM/timestamp/"
fi
echo "[entrypoint] Retenção:   ${BACKUP_RETENTION_DAYS:-7} dias (escopada ao prefix)"

# Roda backup AGORA se RUN_ON_START=true
if [ "${RUN_ON_START:-false}" = "true" ]; then
    echo "[entrypoint] RUN_ON_START=true → executando backup imediato..."
    /app/backup.sh >> /var/log/backup.log 2>&1 &
fi

# Inicia cron e fica fazendo tail dos logs
service cron start
exec tail -f /var/log/backup.log
