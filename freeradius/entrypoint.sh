#!/bin/bash
# =============================================================================
# entrypoint.sh — FreeRADIUS container entrypoint
# 1. Adiciona rota para a rede do SGP via WireGuard
# 2. Envia Accounting-On ao SGP para cada NAS (em background)
# 3. Inicia o FreeRADIUS
# =============================================================================

# Se SGP_ROUTE_GW estiver definido, adiciona rota para as redes do SGP
if [ -n "${SGP_ROUTE_GW}" ]; then
    echo "[entrypoint] Adicionando rota SGP: 172.16.116.0/24 via ${SGP_ROUTE_GW}"
    ip route add 172.16.116.0/24 via "${SGP_ROUTE_GW}" 2>/dev/null || true
    ip route add 172.16.117.0/24 via "${SGP_ROUTE_GW}" 2>/dev/null || true
fi

# Envia Accounting-On ao SGP em background (aguarda 10s para rota estabilizar)
if [ "${SGP_RADIUS_ENABLED:-true}" = "true" ]; then
    (
        sleep 15
        echo "[entrypoint] Enviando Accounting-On ao SGP para todos os NAS..."
        bash /etc/freeradius/3.0/scripts/send_accounting_on.sh
    ) &
fi

exec freeradius -f -l stdout
