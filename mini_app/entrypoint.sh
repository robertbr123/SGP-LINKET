#!/bin/sh
# Adiciona rota para a rede WireGuard dos MikroTiks (10.73.91.0/24)
# para que o mini_app consiga falar via API e enviar CoA disconnect.
WG_IP=$(getent hosts wireguard | awk '{print $1}')
if [ -n "$WG_IP" ]; then
    ip route add 10.73.91.0/24 via "$WG_IP" 2>/dev/null && \
        echo "[entrypoint] Rota 10.73.91.0/24 via $WG_IP adicionada" || \
        echo "[entrypoint] Rota ja existe ou falhou (ignorando)"
fi

exec gunicorn \
    --bind 0.0.0.0:5001 \
    --worker-class gthread \
    --workers 2 \
    --threads 8 \
    --timeout 60 \
    --graceful-timeout 30 \
    --access-logfile - \
    --error-logfile - \
    server:app
