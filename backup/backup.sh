#!/bin/bash
# Backup diário Postgres + Mongo → Cloudflare R2
# Notifica Telegram em sucesso/falha.
set -uo pipefail

LOG_PREFIX="[backup $(date '+%Y-%m-%d %H:%M:%S')]"
DATE=$(date +%Y%m%d_%H%M%S)
WORK_DIR="/backups/$DATE"
mkdir -p "$WORK_DIR"

cleanup() {
    rm -rf "$WORK_DIR"
}
trap cleanup EXIT

notify_telegram() {
    local emoji="$1"; shift
    local msg="$*"
    local token chat
    token=$(PGPASSWORD="$DB_PASS" psql -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" -tAc \
        "SELECT valor FROM alertas_config WHERE chave='telegram_bot_token'" 2>/dev/null | tr -d '[:space:]')
    chat=$(PGPASSWORD="$DB_PASS" psql -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" -tAc \
        "SELECT valor FROM alertas_config WHERE chave='telegram_chat_id'" 2>/dev/null | tr -d '[:space:]')
    if [ -n "$token" ] && [ -n "$chat" ]; then
        curl -s -X POST "https://api.telegram.org/bot$token/sendMessage" \
            -d "chat_id=$chat" \
            -d "parse_mode=HTML" \
            --data-urlencode "text=${emoji} <b>Backup</b>
${msg}" > /dev/null
    fi
}

echo "$LOG_PREFIX Iniciando backup..."

# 1. Postgres
PG_FILE="$WORK_DIR/postgres-$DATE.sql.gz"
echo "$LOG_PREFIX dump postgres → $PG_FILE"
if PGPASSWORD="$DB_PASS" pg_dump -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" --no-owner --no-acl 2>"$WORK_DIR/pg.err" \
   | gzip -9 > "$PG_FILE"; then
    PG_SIZE=$(du -h "$PG_FILE" | cut -f1)
    echo "$LOG_PREFIX postgres OK ($PG_SIZE)"
else
    msg="❌ pg_dump falhou: $(tail -3 "$WORK_DIR/pg.err" | tr '\n' ' ')"
    echo "$LOG_PREFIX $msg"
    notify_telegram "🔴" "$msg"
    exit 1
fi

# 2. Mongo (GenieACS)
MONGO_DIR="$WORK_DIR/mongo"
echo "$LOG_PREFIX dump mongo → $MONGO_DIR"
if mongodump --host="${MONGO_HOST:-mongodb}" --db=genieacs --out="$MONGO_DIR" --quiet 2>"$WORK_DIR/mongo.err"; then
    MONGO_SIZE=$(du -sh "$MONGO_DIR" | cut -f1)
    tar -czf "$WORK_DIR/mongo-$DATE.tar.gz" -C "$WORK_DIR" mongo
    rm -rf "$MONGO_DIR"
    echo "$LOG_PREFIX mongo OK ($MONGO_SIZE)"
else
    msg="⚠️ mongodump falhou: $(tail -3 "$WORK_DIR/mongo.err" | tr '\n' ' ') (continuando com pg apenas)"
    echo "$LOG_PREFIX $msg"
    # Não aborta — continua com Postgres
fi

# 3. Upload pra R2 (rclone)
# R2_PREFIX permite separar backups dentro de um bucket compartilhado.
# Ex: R2_BUCKET=dokploy + R2_PREFIX=SGP-LINKET → dokploy/SGP-LINKET/2026/05/...
PREFIX_PATH="${R2_PREFIX:+${R2_PREFIX}/}"
BASE_PATH="r2:${R2_BUCKET:-sgp-linket-backups}/${PREFIX_PATH}"
R2_REMOTE="${BASE_PATH}$(date +%Y/%m)"
echo "$LOG_PREFIX upload → $R2_REMOTE/$DATE/"
if rclone copy "$WORK_DIR" "$R2_REMOTE/$DATE/" --quiet --transfers 2 --retries 3 \
   --config /tmp/rclone.conf 2>"$WORK_DIR/rclone.err"; then
    echo "$LOG_PREFIX upload OK"
else
    msg="🔴 Upload R2 falhou: $(tail -3 "$WORK_DIR/rclone.err" | tr '\n' ' ')"
    echo "$LOG_PREFIX $msg"
    notify_telegram "🔴" "$msg"
    exit 1
fi

# 4. Retenção: deletar backups com mais de N dias do R2
# IMPORTANTE: a limpeza é escopada SÓ ao prefix do SGP-LINKET — nunca toca
# em arquivos de outras apps que compartilhem o mesmo bucket.
echo "$LOG_PREFIX limpando backups antigos (>${BACKUP_RETENTION_DAYS:-7}d) em ${BASE_PATH}..."
RETENTION_DAYS="${BACKUP_RETENTION_DAYS:-7}"
rclone delete "${BASE_PATH}" \
    --min-age "${RETENTION_DAYS}d" \
    --config /tmp/rclone.conf --quiet 2>/dev/null || true
rclone rmdirs "${BASE_PATH}" \
    --leave-root --config /tmp/rclone.conf --quiet 2>/dev/null || true

# Sucesso
TOTAL_SIZE=$(du -sh "$WORK_DIR" | cut -f1)
SUCCESS_MSG="✅ Backup concluído ($TOTAL_SIZE)
Postgres: $PG_SIZE
Mongo: ${MONGO_SIZE:-falhou}
Destino: $R2_REMOTE/$DATE/
Retenção: ${RETENTION_DAYS} dias"
echo "$LOG_PREFIX $SUCCESS_MSG"
notify_telegram "✅" "$SUCCESS_MSG"
