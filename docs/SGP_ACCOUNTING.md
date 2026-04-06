# SGP-LINKET: Encaminhamento de Accounting para o SGP

## Visão Geral

O FreeRADIUS autentica os clientes PPPoE e recebe o accounting dos MikroTiks.
Como o SGP precisa receber esses dados de accounting para mostrar os clientes
como **online**, o FreeRADIUS encaminha uma cópia de cada pacote de accounting
ao servidor RADIUS do SGP.

## Arquitetura de Rede

```
Cliente PPPoE
    │
    ▼
MikroTik (10.73.91.x via WireGuard)
    │
    │  RADIUS auth + accounting
    │  (porta 1812/1813 via WireGuard)
    ▼
┌─────────────────────────────────────────────────┐
│  Servidor Docker                                │
│                                                 │
│  WireGuard (10.73.91.1 / 172.28.0.2)           │
│      │                                          │
│      ├── radius-forward (iptables DNAT)         │
│      │       │                                  │
│      │       ▼                                  │
│      │   FreeRADIUS (172.28.0.10)               │
│      │       │  1. Autentica via SQL            │
│      │       │  2. Grava accounting no Postgres │
│      │       │  3. Encaminha ao SGP via radclient│
│      │       │                                  │
│      │       ▼                                  │
│      ├── route-sgp (iptables + wg AllowedIPs)   │
│      │       │                                  │
│      │       │  rota: 172.16.116.0/24 dev wg0   │
│      │       │  NAT: MASQUERADE → 10.73.91.1    │
│      │       │                                  │
│      │       ▼                                  │
│      └── WireGuard tunnel (wg0)                 │
│              │                                  │
└──────────────┼──────────────────────────────────┘
               │
               ▼
MikroTik (10.73.91.x)
    │
    │  forward + srcnat masquerade
    │  (10.73.91.1 → 172.16.117.x)
    ▼
L2TP tunnel → SGP (172.16.116.1:2052)
    │
    │  Recebe accounting com:
    │    NAS-IP-Address = 172.16.117.x  ✓
    │    → Marca cliente como ONLINE
    ▼
SGP (Painel Web)
```

---

## Configuração Passo a Passo para Adicionar um Novo MikroTik/NAS

### Pré-requisitos

Para cada MikroTik, você precisa saber:

| Item | Onde encontrar | Exemplo |
|------|---------------|---------|
| **IP WireGuard** | wg-easy UI ou `wg show wg0` | `10.73.91.5` |
| **Public Key WireGuard** | `wg show wg0 allowed-ips` no servidor | `T0IU0nE43dYE...` |
| **IP NAS no SGP** | Painel SGP → NAS → Endereço IP | `172.16.117.12` |
| **Nome L2TP** | MikroTik: `/interface l2tp-client print` | `SGP-L2TP` |

### Passo 1: Descobrir a Public Key do peer MikroTik

```bash
docker exec radius_route_sgp sh -c "wg show wg0 allowed-ips"
```

Saída exemplo:
```
/Ey74amoD4hlyv3tQtnIO1y4YoOXBAUYYyOWb5jOvyM=    10.73.91.2/32       ← MikroTik A
T0IU0nE43dYEtcf+6IvBTVLy4UP5NFXxIglas4UblT0=    10.73.91.5/32       ← MikroTik B (CCR-IPIXUNA)
WQWX8MPBKEbcVSJi/XPOohbG8FRJv2e9rflbxjycOzY=    10.73.91.3/32       ← MikroTik C
```

O IP ao lado identifica qual peer é qual MikroTik.

### Passo 2: Editar o `.env` (ou docker-compose.yml)

Adicione o novo peer e mapeamento:

```env
# Chaves WireGuard dos MikroTiks (separadas por vírgula)
SGP_WG_PEER_KEYS=T0IU0nE43dYEtcf+6IvBTVLy4UP5NFXxIglas4UblT0=,/Ey74amoD4hlyv3tQtnIO1y4YoOXBAUYYyOWb5jOvyM=

# Mapeamento: IP_WireGuard=IP_NAS_SGP (separados por vírgula)
SGP_NAS_IP_MAP=10.73.91.5=172.16.117.12,10.73.91.2=172.16.117.13

# Mapeamento: IP_WireGuard=Nome_Identificador_SGP (separados por vírgula)
SGP_NAS_ID_MAP=10.73.91.5=ONDELINE_NET,10.73.91.2=EIRUNEPE_NET
```

**Formato (sempre o IP WireGuard do lado esquerdo do `=`):**
```
SGP_WG_PEER_KEYS=chave1,chave2,chave3
SGP_NAS_IP_MAP=wg_ip1=sgp_ip1,wg_ip2=sgp_ip2,wg_ip3=sgp_ip3
SGP_NAS_ID_MAP=wg_ip1=nome_sgp1,wg_ip2=nome_sgp2,wg_ip3=nome_sgp3
```

### Passo 3: Comandos no MikroTik (obrigatório em CADA MikroTik)

Execute no terminal de cada MikroTik que tem VPN L2TP com o SGP:

```mikrotik
# Verificar nome da interface L2TP do SGP
/interface l2tp-client print where name~"SGP"

# Regra 1: Permitir forward do WireGuard para o SGP
/ip firewall filter add chain=forward src-address=10.73.91.0/24 dst-address=172.16.116.0/24 action=accept comment="FreeRADIUS -> SGP accounting via L2TP" place-before=0

# Regra 2: NAT para o SGP ver tráfego vindo do IP correto
/ip firewall nat add chain=srcnat src-address=10.73.91.0/24 dst-address=172.16.116.0/24 out-interface=SGP-L2TP action=masquerade comment="NAT FreeRADIUS -> SGP via L2TP"
```

> **IMPORTANTE:** Substitua `SGP-L2TP` pelo nome real da interface L2TP em cada MikroTik.
> O nome aparece no output de `/interface l2tp-client print`.

**Verificar se as regras foram criadas:**
```mikrotik
/ip firewall filter print where comment~"FreeRADIUS"
/ip firewall nat print where comment~"FreeRADIUS"
```

### Passo 4: Aplicar no servidor

```bash
# Rebuild e restart
docker compose build freeradius
docker compose up -d

# Verificar se os AllowedIPs foram atualizados
docker exec radius_route_sgp sh -c "wg show wg0 allowed-ips"

# Testar accounting para o SGP
docker exec radius_freeradius bash /etc/freeradius/3.0/scripts/test_sgp_acct.sh
```

---

## Exemplo Completo: 3 MikroTiks

```
MikroTik IPIXUNA   → WireGuard 10.73.91.5  → SGP NAS 172.16.117.12
MikroTik EIRUNEPE  → WireGuard 10.73.91.2  → SGP NAS 172.16.117.13
MikroTik ITAMARATI → WireGuard 10.73.91.3  → SGP NAS 172.16.117.14
```

### No `.env`:
```env
# Peer keys dos 3 MikroTiks
SGP_WG_PEER_KEYS=T0IU0nE43dYEtcf+6IvBTVLy4UP5NFXxIglas4UblT0=,/Ey74amoD4hlyv3tQtnIO1y4YoOXBAUYYyOWb5jOvyM=,WQWX8MPBKEbcVSJi/XPOohbG8FRJv2e9rflbxjycOzY=

# Mapeamento WireGuard IP → SGP NAS IP
SGP_NAS_IP_MAP=10.73.91.5=172.16.117.12,10.73.91.2=172.16.117.13,10.73.91.3=172.16.117.14

# Mapeamento WireGuard IP → Nome Identificador no SGP
SGP_NAS_ID_MAP=10.73.91.5=ONDELINE_NET,10.73.91.2=EIRUNEPE_NET,10.73.91.3=ITAMARATI_NET
```

### Em CADA MikroTik:
```mikrotik
# Verificar nome da interface L2TP
/interface l2tp-client print where name~"SGP"

# Liberar forward (mesmo comando nos 3)
/ip firewall filter add chain=forward src-address=10.73.91.0/24 dst-address=172.16.116.0/24 action=accept comment="FreeRADIUS -> SGP accounting via L2TP" place-before=0

# NAT (ajustar out-interface conforme o nome do L2TP em cada MikroTik)
/ip firewall nat add chain=srcnat src-address=10.73.91.0/24 dst-address=172.16.116.0/24 out-interface=SGP-L2TP action=masquerade comment="NAT FreeRADIUS -> SGP via L2TP"
```

---

## Variáveis de Ambiente

### Container `route-sgp`

| Variável | Descrição | Padrão |
|----------|-----------|--------|
| `SGP_WG_PEER_KEYS` | Chaves públicas WireGuard dos peers MikroTik (vírgula) | `T0IU0nE43dYE...` |

### Container `freeradius`

| Variável | Descrição | Padrão |
|----------|-----------|--------|
| `SGP_RADIUS_ENABLED` | Ativa/desativa encaminhamento | `true` |
| `SGP_RADIUS_HOST` | IP do servidor RADIUS do SGP | `172.16.116.1` |
| `SGP_RADIUS_ACCT_PORT` | Porta de accounting do SGP | `2052` |
| `SGP_RADIUS_SECRET` | Secret compartilhado | `sgp@radius` |
| `SGP_NAS_IP_MAP` | Mapeamento WireGuard IP → NAS IP no SGP (vírgula) | `10.73.91.5=172.16.117.12` |
| `SGP_NAS_IP_OVERRIDE` | Fallback de NAS IP se não está no mapa | `172.16.117.12` |
| `SGP_NAS_ID_MAP` | Mapeamento WireGuard IP → Nome Identificador no SGP (vírgula) | `10.73.91.5=ONDELINE_NET` |
| `SGP_NAS_IDENTIFIER` | Fallback de Nome Identificador se não está no mapa | `ONDELINE_NET` |
| `SGP_ACCT_DEBUG` | Loga packets no stderr | `false` |

---

## Troubleshooting

### Clientes não aparecem online no SGP

1. **Verificar rota no FreeRADIUS:**
   ```bash
   docker exec radius_freeradius ip route show 172.16.116.0/24
   # Esperado: 172.16.116.0/24 via 172.28.0.2 dev eth0
   ```

2. **Verificar AllowedIPs:**
   ```bash
   docker exec radius_route_sgp sh -c "wg show wg0 allowed-ips"
   # Todos os peers MikroTik devem ter 172.16.116.0/24 e 172.16.117.0/24
   ```

3. **Testar conectividade:**
   ```bash
   docker exec radius_freeradius bash /etc/freeradius/3.0/scripts/test_sgp_acct.sh
   ```

4. **Verificar mapeamento de NAS-IP (ativar debug):**
   ```bash
   # Temporário - não altera o container em execução:
   docker compose exec -e SGP_ACCT_DEBUG=true freeradius env | grep SGP
   
   # Para ver os logs em tempo real, altere no .env e reinicie:
   # SGP_ACCT_DEBUG=true
   docker compose up -d freeradius
   docker logs -f radius_freeradius 2>&1 | grep SGP-ACCT
   ```

5. **Verificar regras no MikroTik:**
   ```mikrotik
   /ip firewall filter print where comment~"FreeRADIUS"
   /ip firewall nat print where comment~"FreeRADIUS"
   ```

### Peer key incorreta

Para descobrir a chave correta de cada MikroTik:
```bash
# No servidor - mostra todas as chaves e seus IPs
docker exec radius_route_sgp sh -c "wg show wg0 allowed-ips"
```
A chave ao lado do IP `10.73.91.X` corresponde ao MikroTik com esse IP WireGuard.

**NÃO confundir com a Public Key do SERVIDOR** que aparece no arquivo `.conf`
do WireGuard. A chave do servidor é a que o MikroTik usa em `[Peer] PublicKey`.
A chave que precisamos é a do MikroTik, que aparece em `wg show wg0`.

### Pacote enviado mas SGP não responde

- Verificar se as regras de firewall/NAT existem no MikroTik
- Verificar se o nome da interface L2TP está correto no NAT
- Verificar se a VPN L2TP do MikroTik com o SGP está conectada:
  ```mikrotik
  /interface l2tp-client print where name~"SGP"
  # O campo "status" deve ser "connected"
  ```

---

## Arquivos Modificados

| Arquivo | Função |
|---------|--------|
| `docker-compose.yml` | Orquestração dos containers e variáveis de ambiente |
| `freeradius/Dockerfile` | Build do FreeRADIUS com iproute2 e entrypoint |
| `freeradius/entrypoint.sh` | Adiciona rota SGP antes de iniciar o FreeRADIUS |
| `freeradius/config/mods-enabled/exec_sgp` | Módulo exec que chama o script de encaminhamento |
| `freeradius/config/sites-enabled/default` | Seção accounting chama `exec_sgp_acct` |
| `freeradius/scripts/forward_acct_to_sgp.sh` | Script que monta e envia o pacote ao SGP |
| `freeradius/scripts/test_sgp_acct.sh` | Script de teste de conectividade com o SGP |

# Exemplo com 3 MikroTiks no .env:

# Peer keys (para o roteamento WireGuard)
SGP_WG_PEER_KEYS=chave_ipixuna,chave_eirunepe,chave_itamarati

# IP do NAS no SGP (campo "Endereço IP" no cadastro do NAS)
SGP_NAS_IP_MAP=10.73.91.5=172.16.117.12,10.73.91.2=172.16.117.13,10.73.91.3=172.16.117.14

# Nome do NAS no SGP (campo "Nome Identificador" no cadastro do NAS)
SGP_NAS_ID_MAP=10.73.91.5=ONDELINE_NET,10.73.91.2=EIRUNEPE_NET,10.73.91.3=ITAMARATI_NET

# Depois aplique (ajuste o nome em out-interface se necessário):
/ip firewall filter add chain=forward src-address=10.73.91.0/24 dst-address=172.16.116.0/24 action=accept comment="FreeRADIUS -> SGP accounting via L2TP" place-before=0

/ip firewall nat add chain=srcnat src-address=10.73.91.0/24 dst-address=172.16.116.0/24 out-interface=SGP-L2TP action=masquerade comment="NAT FreeRADIUS -> SGP via L2TP"
