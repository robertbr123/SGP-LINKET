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

# Grava configuração SGP em arquivo para o script de accounting (exec wait=no não herda env)
SGP_CONF="/etc/freeradius/3.0/sgp_env.conf"
cat > "${SGP_CONF}" <<ENVEOF
SGP_RADIUS_ENABLED=${SGP_RADIUS_ENABLED:-true}
SGP_RADIUS_HOST=${SGP_RADIUS_HOST:-172.16.116.1}
SGP_RADIUS_ACCT_PORT=${SGP_RADIUS_ACCT_PORT:-2052}
SGP_RADIUS_SECRET=${SGP_RADIUS_SECRET:-sgp@radius}
SGP_NAS_IP_MAP=${SGP_NAS_IP_MAP:-}
SGP_NAS_IP_OVERRIDE=${SGP_NAS_IP_OVERRIDE:-172.16.117.12}
SGP_NAS_ID_MAP=${SGP_NAS_ID_MAP:-}
SGP_NAS_IDENTIFIER=${SGP_NAS_IDENTIFIER:-}
SGP_ACCT_DEBUG=${SGP_ACCT_DEBUG:-false}
ENVEOF
chmod 644 "${SGP_CONF}"
echo "[entrypoint] Configuração SGP salva em ${SGP_CONF}"

# Envia Accounting-On ao SGP em background (aguarda 10s para rota estabilizar)
if [ "${SGP_RADIUS_ENABLED:-true}" = "true" ]; then
    (
        sleep 15
        echo "[entrypoint] Enviando Accounting-On ao SGP para todos os NAS..."
        bash /etc/freeradius/3.0/scripts/send_accounting_on.sh
    ) &
fi

exec freeradius -f -l stdout
