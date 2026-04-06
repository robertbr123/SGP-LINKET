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
#   SGP_NAS_IP_MAP           - Mapeamento de NAS-IP original → NAS-IP do SGP.
#                               Formato: "ip_original1=ip_sgp1,ip_original2=ip_sgp2"
#                               Ex.: "10.73.91.5=172.16.117.12,10.73.91.6=172.16.117.13"
#   SGP_NAS_IP_OVERRIDE      - Fallback se o IP não estiver no mapa (ex.: 172.16.117.12)
#   SGP_NAS_ID_MAP           - Mapeamento de NAS-IP original → Nome Identificador no SGP.
#                               Formato: "ip_original1=nome1,ip_original2=nome2"
#                               Ex.: "10.73.91.5=ONDELINE_NET,10.73.91.6=EIRUNEPE_NET"
#   SGP_NAS_IDENTIFIER       - Fallback de NAS-Identifier se o IP não estiver no mapa.
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
# Tradução de NAS-IP-Address para o IP que o SGP conhece.
#
# Prioridade:
#   1. SGP_NAS_IP_MAP  — mapeamento por NAS (múltiplos MikroTiks)
#   2. SGP_NAS_IP_OVERRIDE — fallback único (cenário com 1 MikroTik)
#   3. Sem alteração — usa o IP original do pacote
#
# Formato do SGP_NAS_IP_MAP:
#   "ip_original1=ip_sgp1,ip_original2=ip_sgp2"
#   Ex.: "10.73.91.5=172.16.117.12,10.73.91.6=172.16.117.13"
# ---------------------------------------------------------------------------
ORIGINAL_NAS_IP="${NAS_IP}"
if [ -n "${SGP_NAS_IP_MAP}" ]; then
    MAPPED=$(echo "${SGP_NAS_IP_MAP}" | tr ',' '\n' | grep "^${NAS_IP}=" | head -1 | cut -d= -f2)
    if [ -n "${MAPPED}" ]; then
        NAS_IP="${MAPPED}"
    elif [ -n "${SGP_NAS_IP_OVERRIDE}" ]; then
        NAS_IP="${SGP_NAS_IP_OVERRIDE}"
    fi
elif [ -n "${SGP_NAS_IP_OVERRIDE}" ]; then
    NAS_IP="${SGP_NAS_IP_OVERRIDE}"
fi

# ---------------------------------------------------------------------------
# Tradução do NAS-Identifier (Nome Identificador) por MikroTik.
#
# Prioridade:
#   1. SGP_NAS_ID_MAP   — mapeamento por NAS (múltiplos MikroTiks)
#   2. SGP_NAS_IDENTIFIER — fallback único
#   3. Sem alteração — não envia NAS-Identifier
#
# Formato do SGP_NAS_ID_MAP:
#   "ip_original1=nome1,ip_original2=nome2"
#   Ex.: "10.73.91.5=ONDELINE_NET,10.73.91.6=EIRUNEPE_NET"
# ---------------------------------------------------------------------------
NAS_IDENT="${SGP_NAS_IDENTIFIER}"
if [ -n "${SGP_NAS_ID_MAP}" ]; then
    MAPPED_ID=$(echo "${SGP_NAS_ID_MAP}" | tr ',' '\n' | grep "^${ORIGINAL_NAS_IP}=" | head -1 | cut -d= -f2)
    if [ -n "${MAPPED_ID}" ]; then
        NAS_IDENT="${MAPPED_ID}"
    fi
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

    # NAS-Identifier — identidade textual do NAS (resolvido via SGP_NAS_ID_MAP)
    if [ -n "${NAS_IDENT}" ]; then
        printf 'NAS-Identifier = "%s"\n' "${NAS_IDENT}"
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
    echo "[SGP-ACCT] ${ACCT_STATUS} user=${USER_NAME} nas=${ORIGINAL_NAS_IP}->${NAS_IP} framed=${FRAMED_IP} -> ${SGP_HOST}:${SGP_PORT}" >&2
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
