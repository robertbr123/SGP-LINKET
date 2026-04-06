#!/bin/bash
# =============================================================================
# forward_acct_to_sgp.sh
# Encaminha cópia dos packets de accounting RADIUS ao servidor do SGP.
# Chamado pelo módulo exec do FreeRADIUS a cada evento de accounting.
#
# Variáveis de ambiente (injetadas via docker-compose):
#   SGP_RADIUS_ENABLED   - "true" para ativar (padrão: true)
#   SGP_RADIUS_HOST      - IP do servidor RADIUS do SGP (padrão: 172.16.116.1)
#   SGP_RADIUS_ACCT_PORT - Porta de accounting do SGP (padrão: 2052)
#   SGP_RADIUS_SECRET    - Secret compartilhado (padrão: sgp@radius)
# =============================================================================

# Sai imediatamente se o encaminhamento estiver desativado
[ "${SGP_RADIUS_ENABLED:-true}" = "false" ] && exit 0

# ---------------------------------------------------------------------------
# Argumentos recebidos via expansão %{attr} do FreeRADIUS (shell_escape=yes)
# ---------------------------------------------------------------------------
ACCT_STATUS="${1}"        # Acct-Status-Type  (Start / Stop / Interim-Update)
USER_NAME="${2}"          # User-Name
ACCT_SESSION_ID="${3}"    # Acct-Session-Id
NAS_IP="${4:-0.0.0.0}"   # NAS-IP-Address
FRAMED_IP="${5}"          # Framed-IP-Address
ACCT_SESSION_TIME="${6:-0}"    # Acct-Session-Time
ACCT_INPUT_OCTETS="${7:-0}"    # Acct-Input-Octets
ACCT_OUTPUT_OCTETS="${8:-0}"   # Acct-Output-Octets
CALLING_STATION="${9}"         # Calling-Station-Id (MAC do cliente)
CALLED_STATION="${10}"         # Called-Station-Id  (interface MikroTik)
TERMINATE_CAUSE="${11}"        # Acct-Terminate-Cause (só em Stop)
UNIQUE_SESSION_ID="${12}"      # Acct-Unique-Session-Id

# Se não veio Acct-Status-Type não tem o que encaminhar
[ -z "${ACCT_STATUS}" ] && exit 0

# Se não tem username não faz sentido encaminhar
[ -z "${USER_NAME}" ] && exit 0

# ---------------------------------------------------------------------------
# Destino
# ---------------------------------------------------------------------------
SGP_HOST="${SGP_RADIUS_HOST:-172.16.116.1}"
SGP_PORT="${SGP_RADIUS_ACCT_PORT:-2052}"
SGP_SECRET="${SGP_RADIUS_SECRET:-sgp@radius}"

# ---------------------------------------------------------------------------
# Monta o packet de accounting no formato aceito pelo radclient
# ---------------------------------------------------------------------------
PACKET=$(
    printf 'User-Name = "%s"\n'         "${USER_NAME}"
    printf 'Acct-Status-Type = %s\n'    "${ACCT_STATUS}"
    printf 'Acct-Session-Id = "%s"\n'   "${ACCT_SESSION_ID}"
    printf 'NAS-IP-Address = %s\n'      "${NAS_IP}"
    printf 'Acct-Session-Time = %s\n'   "${ACCT_SESSION_TIME}"
    printf 'Acct-Input-Octets = %s\n'   "${ACCT_INPUT_OCTETS}"
    printf 'Acct-Output-Octets = %s\n'  "${ACCT_OUTPUT_OCTETS}"

    # Atributos opcionais — incluídos somente se presentes
    if [ -n "${FRAMED_IP}" ] && [ "${FRAMED_IP}" != "0.0.0.0" ]; then
        printf 'Framed-IP-Address = %s\n' "${FRAMED_IP}"
    fi
    if [ -n "${CALLING_STATION}" ]; then
        printf 'Calling-Station-Id = "%s"\n' "${CALLING_STATION}"
    fi
    if [ -n "${CALLED_STATION}" ]; then
        printf 'Called-Station-Id = "%s"\n' "${CALLED_STATION}"
    fi
    if [ -n "${TERMINATE_CAUSE}" ]; then
        printf 'Acct-Terminate-Cause = %s\n' "${TERMINATE_CAUSE}"
    fi
    if [ -n "${UNIQUE_SESSION_ID}" ]; then
        printf 'Acct-Unique-Session-Id = "%s"\n' "${UNIQUE_SESSION_ID}"
    fi
)

# ---------------------------------------------------------------------------
# Envia via radclient (-r 1 = 1 tentativa, -t 3 = timeout 3s)
# Saída suprimida para não poluir logs do FreeRADIUS
# ---------------------------------------------------------------------------
printf '%s\n' "${PACKET}" | \
    radclient -r 1 -t 3 "${SGP_HOST}:${SGP_PORT}" acct "${SGP_SECRET}" 2>/dev/null

exit 0
