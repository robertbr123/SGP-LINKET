#!/bin/bash
# =============================================================================
# send_accounting_on.sh
# Envia Accounting-On (e opcionalmente Accounting-Off) ao SGP para cada NAS
# mapeado em SGP_NAS_IP_MAP.
#
# O pacote Accounting-On informa ao SGP que o NAS está ativo e pronto para
# receber sessões. Sem ele, o SGP pode não contar sessões online por NAS.
#
# Uso:
#   send_accounting_on.sh           # Envia Accounting-On para todos os NAS
#   send_accounting_on.sh off       # Envia Accounting-Off para todos os NAS
#
# Variáveis de ambiente esperadas:
#   SGP_RADIUS_HOST, SGP_RADIUS_ACCT_PORT, SGP_RADIUS_SECRET
#   SGP_NAS_IP_MAP, SGP_NAS_ID_MAP
# =============================================================================

SGP_HOST="${SGP_RADIUS_HOST:-172.16.116.1}"
SGP_PORT="${SGP_RADIUS_ACCT_PORT:-2052}"
SGP_SECRET="${SGP_RADIUS_SECRET:-sgp@radius}"
STATUS_TYPE="${1:-on}"

if [ "${STATUS_TYPE}" = "off" ]; then
    ACCT_STATUS="8"
    ACCT_LABEL="Accounting-Off"
    echo "[NAS-ACCT] Enviando Accounting-Off para todos os NAS..."
else
    ACCT_STATUS="7"
    ACCT_LABEL="Accounting-On"
    echo "[NAS-ACCT] Enviando Accounting-On para todos os NAS..."
fi

# Se não tem mapa, usa o override como NAS único
if [ -z "${SGP_NAS_IP_MAP}" ]; then
    NAS_IP="${SGP_NAS_IP_OVERRIDE:-172.16.117.12}"
    NAS_IDENT="${SGP_NAS_IDENTIFIER:-}"

    PACKET="Acct-Status-Type = ${ACCT_STATUS}
NAS-IP-Address = ${NAS_IP}"
    if [ -n "${NAS_IDENT}" ]; then
        PACKET="${PACKET}
NAS-Identifier = ${NAS_IDENT}"
    fi

    echo "[NAS-ACCT]   NAS ${NAS_IP} (${NAS_IDENT:-sem identificador})..."
    RESULT=$(printf '%s\n' "${PACKET}" | radclient -r 2 -t 5 "${SGP_HOST}:${SGP_PORT}" acct "${SGP_SECRET}" 2>&1)
    if [ $? -eq 0 ]; then
        echo "[NAS-ACCT]   OK - SGP aceitou ${ACCT_LABEL} para ${NAS_IP}"
    else
        echo "[NAS-ACCT]   FALHA - ${RESULT}"
    fi
    exit 0
fi

# Itera sobre cada NAS mapeado
echo "${SGP_NAS_IP_MAP}" | tr ',' '\n' | while IFS='=' read -r WG_IP SGP_IP; do
    [ -z "${SGP_IP}" ] && continue

    # Busca o nome identificador correspondente
    NAS_IDENT=""
    if [ -n "${SGP_NAS_ID_MAP}" ]; then
        NAS_IDENT=$(echo "${SGP_NAS_ID_MAP}" | tr ',' '\n' | grep "^${WG_IP}=" | head -1 | cut -d= -f2)
    fi
    [ -z "${NAS_IDENT}" ] && NAS_IDENT="${SGP_NAS_IDENTIFIER:-}"

    PACKET="Acct-Status-Type = ${ACCT_STATUS}
NAS-IP-Address = ${SGP_IP}"
    if [ -n "${NAS_IDENT}" ]; then
        PACKET="${PACKET}
NAS-Identifier = ${NAS_IDENT}"
    fi

    echo "[NAS-ACCT]   NAS ${SGP_IP} (${NAS_IDENT:-sem identificador}) [WG: ${WG_IP}]..."
    RESULT=$(printf '%s\n' "${PACKET}" | radclient -r 2 -t 5 "${SGP_HOST}:${SGP_PORT}" acct "${SGP_SECRET}" 2>&1)
    if [ $? -eq 0 ]; then
        echo "[NAS-ACCT]   OK - SGP aceitou ${ACCT_LABEL}"
    else
        echo "[NAS-ACCT]   FALHA - ${RESULT}"
    fi
done

echo "[NAS-ACCT] Concluido."
