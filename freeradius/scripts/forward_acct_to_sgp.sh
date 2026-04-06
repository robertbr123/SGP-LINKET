#!/bin/bash
# =============================================================================
# forward_acct_to_sgp.sh
# Encaminha cópia dos packets de accounting RADIUS ao servidor do SGP.
# Chamado pelo módulo exec do FreeRADIUS a cada evento de accounting.
#
# Variáveis de ambiente (injetadas via docker-compose):
#   SGP_RADIUS_ENABLED       - "true" para ativar (padrão: true)
#   SGP_RADIUS_HOST          - IP do servidor RADIUS do SGP (padrão: 172.16.116.1)
#   SGP_RADIUS_ACCT_PORT     - Porta de accounting do SGP (padrão: 2052)
#   SGP_RADIUS_SECRET        - Secret compartilhado (padrão: sgp@radius)
#   SGP_NAS_IP_OVERRIDE      - Substitui NAS-IP-Address no pacote enviado ao SGP
#                               (usar o IP do MikroTik na rede L2TP do SGP,
#                                ex.: 172.16.117.12). Se vazio, usa o IP original.
#   SGP_NAS_IDENTIFIER       - NAS-Identifier enviado ao SGP (ex.: MikroTik).
#                               Se vazio, não envia o atributo.
#   SGP_ACCT_DEBUG           - "true" para logar cada envio em stderr (padrão: false)
# =============================================================================

# Sai imediatamente se o encaminhamento estiver desativado
[ "${SGP_RADIUS_ENABLED:-true}" = "false" ] && exit 0

# ---------------------------------------------------------------------------
# Argumentos recebidos via expansão %{attr} do FreeRADIUS (shell_escape=yes)
# ---------------------------------------------------------------------------
ACCT_STATUS="${1}"             # Acct-Status-Type  (Start / Stop / Interim-Update)
USER_NAME="${2}"               # User-Name
ACCT_SESSION_ID="${3}"         # Acct-Session-Id
NAS_IP="${4:-0.0.0.0}"        # NAS-IP-Address (original do MikroTik)
FRAMED_IP="${5}"               # Framed-IP-Address
ACCT_SESSION_TIME="${6:-0}"    # Acct-Session-Time
ACCT_INPUT_OCTETS="${7:-0}"    # Acct-Input-Octets
ACCT_OUTPUT_OCTETS="${8:-0}"   # Acct-Output-Octets
CALLING_STATION="${9}"         # Calling-Station-Id (MAC do cliente)
CALLED_STATION="${10}"         # Called-Station-Id  (interface MikroTik)
TERMINATE_CAUSE="${11}"        # Acct-Terminate-Cause (só em Stop)
UNIQUE_SESSION_ID="${12}"      # Acct-Unique-Session-Id
NAS_PORT_TYPE="${13}"          # NAS-Port-Type (Virtual, Ethernet, etc.)
NAS_PORT="${14}"               # NAS-Port
SERVICE_TYPE="${15}"           # Service-Type (Framed-User, etc.)
FRAMED_PROTOCOL="${16}"        # Framed-Protocol (PPP, etc.)

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
# Override do NAS-IP-Address — ESSENCIAL para o SGP reconhecer o NAS
# O SGP tem o NAS cadastrado com o IP da interface L2TP do MikroTik
# (ex.: 172.16.117.12), mas o MikroTik envia accounting ao FreeRADIUS
# com outro IP. Sem o override, o SGP ignora o pacote.
# ---------------------------------------------------------------------------
if [ -n "${SGP_NAS_IP_OVERRIDE}" ]; then
    NAS_IP="${SGP_NAS_IP_OVERRIDE}"
fi

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

    # NAS-Port-Type — indica ao SGP o tipo de conexão (Virtual = PPPoE/VPN)
    if [ -n "${NAS_PORT_TYPE}" ]; then
        printf 'NAS-Port-Type = %s\n' "${NAS_PORT_TYPE}"
    else
        printf 'NAS-Port-Type = Virtual\n'
    fi

    # Service-Type — identifica tipo de serviço (Framed-User para PPPoE)
    if [ -n "${SERVICE_TYPE}" ]; then
        printf 'Service-Type = %s\n' "${SERVICE_TYPE}"
    else
        printf 'Service-Type = Framed-User\n'
    fi

    # Framed-Protocol — protocolo do enlace (PPP para PPPoE)
    if [ -n "${FRAMED_PROTOCOL}" ]; then
        printf 'Framed-Protocol = %s\n' "${FRAMED_PROTOCOL}"
    else
        printf 'Framed-Protocol = PPP\n'
    fi

    # NAS-Port — porta lógica no concentrador
    if [ -n "${NAS_PORT}" ]; then
        printf 'NAS-Port = %s\n' "${NAS_PORT}"
    fi

    # NAS-Identifier — identidade textual do NAS (opcional)
    if [ -n "${SGP_NAS_IDENTIFIER}" ]; then
        printf 'NAS-Identifier = "%s"\n' "${SGP_NAS_IDENTIFIER}"
    fi

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
# Debug — loga conteúdo do packet quando SGP_ACCT_DEBUG=true
# ---------------------------------------------------------------------------
if [ "${SGP_ACCT_DEBUG:-false}" = "true" ]; then
    echo "[SGP-ACCT] ${ACCT_STATUS} user=${USER_NAME} nas=${NAS_IP} framed=${FRAMED_IP} -> ${SGP_HOST}:${SGP_PORT}" >&2
    echo "${PACKET}" >&2
fi

# ---------------------------------------------------------------------------
# Envia via radclient (-r 2 = 2 tentativas, -t 3 = timeout 3s)
# Em modo debug loga resultado; em produção suprime para não poluir logs.
# ---------------------------------------------------------------------------
if [ "${SGP_ACCT_DEBUG:-false}" = "true" ]; then
    printf '%s\n' "${PACKET}" | \
        radclient -r 2 -t 3 "${SGP_HOST}:${SGP_PORT}" acct "${SGP_SECRET}" 2>&1 | \
        while IFS= read -r line; do echo "[SGP-ACCT] radclient: ${line}" >&2; done
else
    printf '%s\n' "${PACKET}" | \
        radclient -r 2 -t 3 "${SGP_HOST}:${SGP_PORT}" acct "${SGP_SECRET}" >/dev/null 2>&1
fi

exit 0
