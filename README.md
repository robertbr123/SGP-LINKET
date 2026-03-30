# Todos os serviços ao mesmo tempo (com scroll em tempo real)
docker compose logs -f

# Só o FreeRADIUS
docker compose logs -f freeradius

# Só o painel web
docker compose logs -f web

# Só o sync com SGP
docker compose logs -f sync

# Últimas 100 linhas de um serviço
docker compose logs --tail=100 freeradius



# RADIUS Manager — PPPoE para MikroTik com SGP

Sistema completo de autenticação RADIUS para clientes PPPoE em MikroTik, com integração automática ao ERP SGP.

## Como funciona

```
MikroTik PPPoE ──► FreeRADIUS ──► PostgreSQL (radcheck/radreply)
                                        ▲
                       Painel Web ──────┤
                       Sync SGP  ───────┘
```

1. Você cadastra o cliente no painel web (nome, CPF, plano, velocidade).
2. Na hora do cadastro, o sistema consulta o SGP pelo CPF e obtém o `contratoCentralLogin` (usuário PPPoE) e o status.
3. Se **Ativo** → insere no RADIUS com senha `123` e limite de velocidade.
4. Se **Suspenso** → insere `Auth-Type = Reject` → MikroTik nega a conexão.
5. A cada 5 minutos o serviço `sync` reconfere todos os clientes no SGP e atualiza automaticamente.

## Pré-requisitos

- Docker + Docker Compose
- Porta `1812/udp` e `1813/udp` acessíveis pelo MikroTik

## Subir o sistema

```bash
docker compose up -d --build
```

Painel web disponível em: **http://SEU_IP:5000**

## Configurar o MikroTik

No terminal do MikroTik (Winbox ou SSH):

```
/radius
add address=<IP_DO_SERVIDOR_RADIUS> secret=radiussecret service=ppp

/ppp aaa
set use-radius=yes accounting=yes
```

> O `secret` padrão é `radiussecret`. Troque em `docker-compose.yml` (variável não exposta) e no arquivo `freeradius/config/clients.conf`.

Depois adicione o IP do MikroTik no painel em **NAS / MikroTik**.

## Variáveis de ambiente importantes

| Variável | Padrão | Descrição |
|---|---|---|
| `SECRET_KEY` | (troque!) | Chave Flask para sessões |
| `SYNC_INTERVAL` | `300` | Intervalo de sync com SGP (segundos) |
| `DB_PASS` | `radiuspassword` | Senha do PostgreSQL |

## Estrutura de arquivos

```
RADIUS/
├── docker-compose.yml
├── sql/
│   └── init.sql              # Schema do banco
├── freeradius/
│   ├── Dockerfile
│   └── config/
│       ├── clients.conf      # IPs dos MikroTiks autorizados
│       ├── sites-enabled/default
│       └── mods-enabled/sql
├── web/                      # Painel Flask
│   ├── app.py
│   ├── templates/
│   └── Dockerfile
└── sync/                     # Sincronização automática com SGP
    ├── sync.py
    └── Dockerfile
```

## Segurança recomendada para produção

- Troque `SECRET_KEY` e `DB_PASS` no `docker-compose.yml`
- Troque `radiussecret` no `clients.conf` e no MikroTik
- Coloque o painel web atrás de um proxy reverso (nginx) com HTTPS
- Restrinja o `clients.conf` apenas ao IP real do seu MikroTik (em vez de `0.0.0.0/0`)
