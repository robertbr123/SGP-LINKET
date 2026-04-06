#!/bin/bash
# =============================================================================
# entrypoint.sh — FreeRADIUS container entrypoint
# Adiciona rota para a rede do SGP via WireGuard antes de iniciar o FreeRADIUS.
# =============================================================================

# Se SGP_ROUTE_GW estiver definido, adiciona rota para as redes do SGP
if [ -n "${SGP_ROUTE_GW}" ]; then
    echo "[entrypoint] Adicionando rota SGP: 172.16.116.0/24 via ${SGP_ROUTE_GW}"
    ip route add 172.16.116.0/24 via "${SGP_ROUTE_GW}" 2>/dev/null || true
    ip route add 172.16.117.0/24 via "${SGP_ROUTE_GW}" 2>/dev/null || true
fi

exec freeradius -f -l stdout
