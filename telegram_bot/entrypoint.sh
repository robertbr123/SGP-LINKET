#!/bin/sh
# Adiciona rota para a rede WireGuard dos MikroTiks (10.73.91.0/24)
# para que o radclient (CoA disconnect) consiga falar com o NAS.
WG_IP=$(getent hosts wireguard | awk '{print $1}')
if [ -n "$WG_IP" ]; then
    ip route add 10.73.91.0/24 via "$WG_IP" 2>/dev/null && \
        echo "[entrypoint] Rota 10.73.91.0/24 via $WG_IP adicionada" || \
        echo "[entrypoint] Rota ja existe ou falhou (ignorando)"
else
    echo "[entrypoint] AVISO: nao foi possivel resolver 'wireguard'"
fi

exec python -u bot.py
