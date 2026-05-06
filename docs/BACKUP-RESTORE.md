# Backup e Restore — SGP-LINKET

Sistema de backup automático de Postgres + Mongo (GenieACS) para Cloudflare R2.

## Configuração

No `.env`:

```bash
R2_ACCOUNT_ID=<seu Account ID do Cloudflare>
R2_ACCESS_KEY_ID=<sua key>
R2_SECRET_ACCESS_KEY=<seu secret>
R2_BUCKET=dokploy                 # nome do seu bucket
R2_PREFIX=SGP-LINKET              # subpasta dentro do bucket (opcional)
BACKUP_HOUR=3                     # 03:00 da manhã, fuso do container
BACKUP_MINUTE=0
BACKUP_RETENTION_DAYS=7           # retém últimos 7 dias
```

## Como funciona

- Container `radius_backup` roda cron interno
- Todo dia às `BACKUP_HOUR` faz dump de Postgres + Mongo
- Compacta em `.sql.gz` e `.tar.gz`
- Envia pro R2 via rclone
- Limpa backups com mais de `BACKUP_RETENTION_DAYS` dias (escopada ao prefix)
- Notifica Telegram em sucesso/falha

## Estrutura no R2

```
dokploy/                          ← R2_BUCKET
└── SGP-LINKET/                   ← R2_PREFIX (vazio = backup direto na raiz)
    └── 2026/
        ├── 05/
        │   ├── 20260506_030000/
        │   │   ├── postgres-20260506_030000.sql.gz
        │   │   └── mongo-20260506_030000.tar.gz
        │   ├── 20260507_030000/
        │   └── ...
        └── 06/
```

## Rodar backup imediato (sem esperar 03h)

```bash
# Modo 1: setando RUN_ON_START
echo "BACKUP_RUN_ON_START=true" >> .env
docker compose up -d backup
docker compose logs -f backup
# depois reverter
sed -i 's/BACKUP_RUN_ON_START=true/BACKUP_RUN_ON_START=false/' .env
docker compose up -d backup

# Modo 2: rodar o script direto no container
docker exec radius_backup /app/backup.sh
```

---

## RESTORE — passo a passo

### 1. Listar backups disponíveis

```bash
# Por mês
docker exec radius_backup rclone ls r2:dokploy/SGP-LINKET/2026/05/ --config /tmp/rclone.conf

# Tudo (cuidado, lista todos)
docker exec radius_backup rclone ls r2:dokploy/SGP-LINKET/ --config /tmp/rclone.conf | head -30

# Pelo painel R2 também: Cloudflare → R2 → dokploy → SGP-LINKET/
```

### 2. Baixar um backup específico

```bash
# Substituir 20260506_030000 pela timestamp desejada
DATA=20260506_030000
docker exec radius_backup mkdir -p /restore
docker exec radius_backup rclone copy \
    "r2:dokploy/SGP-LINKET/2026/05/${DATA}/" \
    "/restore/${DATA}/" \
    --config /tmp/rclone.conf

# Listar o que foi baixado
docker exec radius_backup ls -lh /restore/${DATA}/
```

### 3. Restaurar Postgres

⚠️ **Cuidado**: o restore é destrutivo. Faça antes um backup do estado atual se valer a pena.

```bash
DATA=20260506_030000

# Copia do container backup pra dentro do container postgres
docker exec radius_backup cat /restore/${DATA}/postgres-${DATA}.sql.gz | \
    docker exec -i radius_postgres bash -c "gunzip | psql -U radius -d radius"
```

Alternativa em 2 passos:
```bash
# Passo 1: copia o arquivo pro host
docker cp radius_backup:/restore/${DATA}/postgres-${DATA}.sql.gz /tmp/

# Passo 2: restaura
gunzip -c /tmp/postgres-${DATA}.sql.gz | \
    docker exec -i radius_postgres psql -U radius -d radius
```

### 4. Restaurar Mongo (GenieACS)

```bash
DATA=20260506_030000

# Extrai o tar.gz
docker exec radius_backup tar -xzf /restore/${DATA}/mongo-${DATA}.tar.gz -C /restore/

# Copia do container backup pro mongo (precisa passar pelo host)
docker cp radius_backup:/restore/mongo /tmp/mongo-restore
docker cp /tmp/mongo-restore radius_genieacs_mongo:/tmp/

# Restaura (--drop apaga as collections antes)
docker exec radius_genieacs_mongo mongorestore --drop --db genieacs /tmp/mongo-restore/genieacs
```

### 5. Reiniciar serviços que usam o banco

```bash
docker compose restart freeradius web sync telegram-bot mini-app genieacs-cwmp genieacs-nbi genieacs-ui
```

### 6. Limpar a pasta /restore (opcional)

```bash
docker exec radius_backup rm -rf /restore
```

---

## Restore parcial (só uma tabela)

```bash
DATA=20260506_030000

# Extrai o dump pro host
docker cp radius_backup:/restore/${DATA}/postgres-${DATA}.sql.gz /tmp/
gunzip /tmp/postgres-${DATA}.sql.gz

# Copia uma tabela específica (ex: clientes)
docker exec -i radius_postgres pg_restore -U radius -d radius \
    --table=clientes --data-only < /tmp/postgres-${DATA}.sql

# Ou edite o .sql à mão e mande os comandos relevantes
```

---

## Verificar que o backup tá saudável

```bash
# Logs do container
docker compose logs --tail 50 backup

# Status do cron
docker exec radius_backup ps aux | grep cron

# Última mensagem do log
docker exec radius_backup tail /var/log/backup.log

# Ver config rclone (sem expor secret completo)
docker exec radius_backup head /tmp/rclone.conf

# Testar conectividade com R2
docker exec radius_backup rclone lsd r2: --config /tmp/rclone.conf
```

---

## Trocar de storage (S3, Backblaze, etc)

O sistema usa `rclone` que suporta dezenas de provedores. Pra trocar, edite
`backup/entrypoint.sh` (a seção `cat > /tmp/rclone.conf`) e ajuste o `endpoint`
e `provider`. Configurações comuns:

| Provider | Config rclone |
|---|---|
| AWS S3 | `provider = AWS`, `region = us-east-1`, sem `endpoint` |
| Backblaze B2 | `type = b2`, usa `account` + `key` |
| Wasabi | `provider = Wasabi`, `endpoint = s3.wasabisys.com` |
| MinIO local | `provider = Minio`, `endpoint = http://minio:9000` |

Doc completa: https://rclone.org/overview/

---

## Anti-gotchas

- **Não delete o bucket inteiro pelo painel R2 sem backup local primeiro** — sim, isso já aconteceu com mais gente do que você imagina.
- **R2 não tem versionamento de objetos**: se sobrescrever, perdeu. Mas o nosso esquema usa timestamp na pasta, então cada execução vai pra um lugar diferente — não há sobrescrita.
- **Retenção é escopada por prefix**: a limpeza de 7 dias só apaga arquivos dentro de `dokploy/SGP-LINKET/`. Outras apps no mesmo bucket ficam intactas.
- **Restauração de mongo precisa do mongo rodando** antes — não tente restaurar com `mongodb` parado.
- **pg_restore vs psql**: nosso dump é via `pg_dump | gzip` (formato plain), então restauração é com `psql`, não `pg_restore`.
