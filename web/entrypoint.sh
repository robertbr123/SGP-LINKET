#!/bin/sh
# Adiciona rota para a subnet do WireGuard VPN (10.73.91.0/24)
# via o container wireguard, para que o web possa acessar MikroTik via API
WG_IP=$(getent hosts wireguard | awk '{print $1}')
if [ -n "$WG_IP" ]; then
    ip route add 10.73.91.0/24 via "$WG_IP" 2>/dev/null && \
        echo "[entrypoint] Rota 10.73.91.0/24 via $WG_IP adicionada" || \
        echo "[entrypoint] Rota ja existe ou falhou (ignorando)"
else
    echo "[entrypoint] AVISO: nao foi possivel resolver 'wireguard' — rota nao adicionada"
fi

# Rodar migrations Alembic. Em DB existente (com schema já criado),
# se a tabela alembic_version não existir, marca como aplicada (stamp).
echo "[entrypoint] Verificando estado de migrations Alembic..."
ALEMBIC_VERSION_EXISTS=$(PGPASSWORD="$DB_PASS" psql -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" -tAc \
    "SELECT 1 FROM information_schema.tables WHERE table_name='alembic_version'" 2>/dev/null)

if [ "$ALEMBIC_VERSION_EXISTS" != "1" ]; then
    # Banco existente sem alembic_version — verifica se tem schema antigo
    HAS_SCHEMA=$(PGPASSWORD="$DB_PASS" psql -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" -tAc \
        "SELECT 1 FROM information_schema.tables WHERE table_name='clientes'" 2>/dev/null)
    if [ "$HAS_SCHEMA" = "1" ]; then
        echo "[entrypoint] Schema legado detectado — marcando baseline como aplicada (stamp)..."
        alembic stamp 0001 || echo "[entrypoint] WARN: alembic stamp falhou"
    fi
fi

echo "[entrypoint] Aplicando migrations pendentes..."
alembic upgrade head || echo "[entrypoint] WARN: alembic upgrade head falhou (continuando)"

exec gunicorn \
    --bind 0.0.0.0:5000 \
    --worker-class gevent \
    --workers 4 \
    --worker-connections 1000 \
    --timeout 120 \
    --graceful-timeout 30 \
    --keep-alive 5 \
    --access-logfile - \
    --error-logfile - \
    --log-level info \
    app:app
