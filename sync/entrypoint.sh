#!/bin/sh
# Adiciona rota para a subnet do WireGuard VPN (10.73.91.0/24)
# via o container wireguard, para que o sync possa acessar MikroTik via API.
WG_IP=$(getent hosts wireguard | awk '{print $1}')
if [ -n "$WG_IP" ]; then
    ip route add 10.73.91.0/24 via "$WG_IP" 2>/dev/null && \
        echo "[entrypoint] Rota 10.73.91.0/24 via $WG_IP adicionada" || \
        echo "[entrypoint] Rota ja existe ou falhou (ignorando)"
else
    echo "[entrypoint] AVISO: nao foi possivel resolver 'wireguard' — rota nao adicionada"
fi

exec python -u sync.py
