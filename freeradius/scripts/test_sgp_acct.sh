#!/bin/bash
# =============================================================================
# test_sgp_acct.sh
# Envia um pacote de accounting de TESTE ao SGP para validar conectividade
# e verificar se o SGP aceita/responde.
#
# Uso (dentro do container freeradius):
#   bash /etc/freeradius/3.0/scripts/test_sgp_acct.sh
#
# Ou via docker:
#   docker exec radius_freeradius bash /etc/freeradius/3.0/scripts/test_sgp_acct.sh
# =============================================================================

SGP_HOST="${SGP_RADIUS_HOST:-172.16.116.1}"
SGP_PORT="${SGP_RADIUS_ACCT_PORT:-2052}"
SGP_SECRET="${SGP_RADIUS_SECRET:-sgp@radius}"
NAS_IP="${SGP_NAS_IP_OVERRIDE:-172.16.117.12}"

echo "============================================"
echo " Teste de Accounting para SGP"
echo "============================================"
echo " Destino:    ${SGP_HOST}:${SGP_PORT}"
echo " Secret:     ${SGP_SECRET}"
echo " NAS-IP:     ${NAS_IP}"
echo "============================================"
echo ""

# Teste 1: Conectividade de rede
echo "[1/3] Testando conectividade de rede..."
if command -v ping >/dev/null 2>&1; then
    if ping -c 1 -W 3 "${SGP_HOST}" >/dev/null 2>&1; then
        echo "  OK - ${SGP_HOST} acessivel via ICMP"
    else
        echo "  AVISO - ${SGP_HOST} nao respondeu ICMP (pode ter firewall bloqueando ping)"
    fi
else
    echo "  SKIP - ping nao disponivel"
fi
echo ""

# Teste 2: Status request
echo "[2/3] Enviando Status-Server ao SGP..."
echo "Status-Server" | radclient -r 1 -t 5 "${SGP_HOST}:${SGP_PORT}" status "${SGP_SECRET}" 2>&1
RESULT=$?
if [ $RESULT -eq 0 ]; then
    echo "  OK - SGP respondeu ao Status-Server"
else
    echo "  AVISO - SGP nao respondeu Status-Server (codigo: ${RESULT})"
    echo "  (Alguns servidores nao respondem Status-Server, isso pode ser normal)"
fi
echo ""

# Teste 3: Accounting Start de teste
echo "[3/3] Enviando Accounting-Start de teste..."
TEST_SESSION="TEST-$(date +%s)"
PACKET=$(cat <<EOF
User-Name = "teste-sgp-conectividade"
Acct-Status-Type = Start
Acct-Session-Id = "${TEST_SESSION}"
NAS-IP-Address = ${NAS_IP}
NAS-Port-Type = Virtual
Service-Type = Framed-User
Framed-Protocol = PPP
Framed-IP-Address = 10.255.255.254
Calling-Station-Id = "AA:BB:CC:DD:EE:FF"
Acct-Session-Time = 0
Acct-Input-Octets = 0
Acct-Output-Octets = 0
EOF
)

echo "  Pacote:"
echo "${PACKET}" | sed 's/^/    /'
echo ""

echo "${PACKET}" | radclient -r 2 -t 5 "${SGP_HOST}:${SGP_PORT}" acct "${SGP_SECRET}" 2>&1
RESULT=$?
if [ $RESULT -eq 0 ]; then
    echo ""
    echo "  OK - SGP aceitou o pacote de accounting!"
    echo ""
    echo "  >>> Enviando Accounting-Stop para limpar a sessao de teste..."
    STOP_PACKET=$(cat <<EOF
User-Name = "teste-sgp-conectividade"
Acct-Status-Type = Stop
Acct-Session-Id = "${TEST_SESSION}"
NAS-IP-Address = ${NAS_IP}
NAS-Port-Type = Virtual
Service-Type = Framed-User
Framed-Protocol = PPP
Framed-IP-Address = 10.255.255.254
Calling-Station-Id = "AA:BB:CC:DD:EE:FF"
Acct-Session-Time = 5
Acct-Input-Octets = 0
Acct-Output-Octets = 0
Acct-Terminate-Cause = Admin-Reset
EOF
)
    echo "${STOP_PACKET}" | radclient -r 2 -t 5 "${SGP_HOST}:${SGP_PORT}" acct "${SGP_SECRET}" 2>&1
    echo "  Sessao de teste encerrada."
else
    echo ""
    echo "  FALHA - SGP nao aceitou o pacote (codigo: ${RESULT})"
    echo ""
    echo "  Possiveis causas:"
    echo "    1. Rota para ${SGP_HOST} nao existe (verifique L2TP/VPN)"
    echo "    2. Secret incorreto (verifique SGP_RADIUS_SECRET)"
    echo "    3. NAS-IP ${NAS_IP} nao cadastrado no SGP"
    echo "    4. Porta ${SGP_PORT} bloqueada por firewall"
    echo "    5. Servico RADIUS do SGP nao esta rodando"
fi
echo ""
echo "============================================"
echo " Teste concluido"
echo "============================================"
