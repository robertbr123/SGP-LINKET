"""baseline schema (snapshot after Mini App Fase G)

Esta migração contém TODO o schema atual com IF NOT EXISTS — segura
de aplicar em banco existente. Em deploys novos, cria do zero.
Em deploys existentes (com schema já criado pelo init.sql/migrate.sql),
basta executar `alembic stamp 0001` para marcar como aplicada sem rodar SQL.

Revision ID: 0001
Revises:
Create Date: 2026-05-06
"""
from alembic import op


revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


SCHEMA_SQL = r"""
CREATE TABLE IF NOT EXISTS planos (
    id SERIAL PRIMARY KEY,
    nome VARCHAR(100) NOT NULL UNIQUE,
    velocidade_down INTEGER NOT NULL DEFAULT 10,
    velocidade_up INTEGER NOT NULL DEFAULT 5,
    criado_em TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS pools (
    id SERIAL PRIMARY KEY,
    nome VARCHAR(100) NOT NULL UNIQUE,
    range_inicio VARCHAR(15) NOT NULL,
    range_fim VARCHAR(15) NOT NULL,
    descricao VARCHAR(200),
    criado_em TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS clientes (
    id SERIAL PRIMARY KEY,
    nome VARCHAR(200) NOT NULL,
    cpf VARCHAR(20) NOT NULL UNIQUE,
    ip VARCHAR(15),
    plano VARCHAR(100) NOT NULL,
    velocidade_down INTEGER NOT NULL DEFAULT 10,
    velocidade_up INTEGER NOT NULL DEFAULT 5,
    plano_id INTEGER REFERENCES planos(id) ON DELETE SET NULL,
    pool_id INTEGER REFERENCES pools(id) ON DELETE SET NULL,
    pppoe_login VARCHAR(100),
    status VARCHAR(20) NOT NULL DEFAULT 'pendente',
    ultimo_sync_em TIMESTAMP,
    criado_em TIMESTAMP DEFAULT NOW(),
    atualizado_em TIMESTAMP DEFAULT NOW()
);
CREATE UNIQUE INDEX IF NOT EXISTS clientes_pppoe_login_unique
    ON clientes (pppoe_login)
    WHERE pppoe_login IS NOT NULL AND pppoe_login != '';

CREATE TABLE IF NOT EXISTS radcheck (
    id SERIAL PRIMARY KEY,
    username VARCHAR(64) NOT NULL DEFAULT '',
    attribute VARCHAR(64) NOT NULL DEFAULT '',
    op CHAR(2) NOT NULL DEFAULT '==',
    value VARCHAR(253) NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS radcheck_username ON radcheck (username);

CREATE TABLE IF NOT EXISTS radreply (
    id SERIAL PRIMARY KEY,
    username VARCHAR(64) NOT NULL DEFAULT '',
    attribute VARCHAR(64) NOT NULL DEFAULT '',
    op CHAR(2) NOT NULL DEFAULT '=',
    value VARCHAR(253) NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS radreply_username ON radreply (username);

CREATE TABLE IF NOT EXISTS radusergroup (
    id SERIAL PRIMARY KEY,
    username VARCHAR(64) NOT NULL DEFAULT '',
    groupname VARCHAR(64) NOT NULL DEFAULT '',
    priority INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS radusergroup_username ON radusergroup (username);

CREATE TABLE IF NOT EXISTS radgroupcheck (
    id SERIAL PRIMARY KEY,
    groupname VARCHAR(64) NOT NULL DEFAULT '',
    attribute VARCHAR(64) NOT NULL DEFAULT '',
    op CHAR(2) NOT NULL DEFAULT '==',
    value VARCHAR(253) NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS radgroupreply (
    id SERIAL PRIMARY KEY,
    groupname VARCHAR(64) NOT NULL DEFAULT '',
    attribute VARCHAR(64) NOT NULL DEFAULT '',
    op CHAR(2) NOT NULL DEFAULT '=',
    value VARCHAR(253) NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS radacct (
    radacctid BIGSERIAL PRIMARY KEY,
    acctsessionid VARCHAR(64) NOT NULL DEFAULT '',
    acctuniqueid VARCHAR(32) NOT NULL DEFAULT '' UNIQUE,
    username VARCHAR(64) NOT NULL DEFAULT '',
    realm VARCHAR(64) DEFAULT '',
    nasipaddress INET NOT NULL,
    nasportid VARCHAR(15) DEFAULT NULL,
    nasporttype VARCHAR(32) DEFAULT NULL,
    acctstarttime TIMESTAMP WITH TIME ZONE,
    acctupdatetime TIMESTAMP WITH TIME ZONE,
    acctstoptime TIMESTAMP WITH TIME ZONE,
    acctinterval INTEGER,
    acctsessiontime INTEGER,
    acctauthentic VARCHAR(32) DEFAULT NULL,
    connectinfo_start VARCHAR(50) DEFAULT NULL,
    connectinfo_stop VARCHAR(50) DEFAULT NULL,
    acctinputoctets BIGINT,
    acctoutputoctets BIGINT,
    calledstationid VARCHAR(50) NOT NULL DEFAULT '',
    callingstationid VARCHAR(50) NOT NULL DEFAULT '',
    acctterminatecause VARCHAR(32) DEFAULT NULL,
    servicetype VARCHAR(32) DEFAULT NULL,
    framedprotocol VARCHAR(32) DEFAULT NULL,
    framedipaddress INET DEFAULT NULL,
    framedipv6address INET DEFAULT NULL,
    framedipv6prefix INET DEFAULT NULL,
    framedinterfaceid VARCHAR(44) DEFAULT NULL,
    delegatedipv6prefix INET DEFAULT NULL,
    class VARCHAR(64) DEFAULT NULL
);
CREATE INDEX IF NOT EXISTS radacct_username_stoptime ON radacct (username, acctstoptime);
CREATE INDEX IF NOT EXISTS radacct_username ON radacct (username);
CREATE INDEX IF NOT EXISTS radacct_nasipaddress ON radacct (nasipaddress);
CREATE INDEX IF NOT EXISTS radacct_starttime ON radacct (acctstarttime DESC);
CREATE INDEX IF NOT EXISTS radacct_stoptime ON radacct (acctstoptime);

CREATE TABLE IF NOT EXISTS nas (
    id SERIAL PRIMARY KEY,
    nasname VARCHAR(128) NOT NULL,
    shortname VARCHAR(32),
    type VARCHAR(30) DEFAULT 'other',
    ports INTEGER,
    secret VARCHAR(60) NOT NULL DEFAULT 'secret',
    server VARCHAR(64),
    community VARCHAR(50),
    description VARCHAR(200) DEFAULT 'RADIUS Client',
    mikrotik_user VARCHAR(64) DEFAULT 'admin',
    mikrotik_pass VARCHAR(64) DEFAULT '',
    mikrotik_port INTEGER DEFAULT 8728
);

CREATE TABLE IF NOT EXISTS radpostauth (
    id BIGSERIAL PRIMARY KEY,
    username VARCHAR(64) NOT NULL DEFAULT '',
    pass VARCHAR(64) NOT NULL DEFAULT '',
    reply VARCHAR(32) NOT NULL DEFAULT '',
    authdate TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS radpostauth_username ON radpostauth (username);
CREATE INDEX IF NOT EXISTS radpostauth_authdate ON radpostauth (authdate DESC);

CREATE TABLE IF NOT EXISTS usuarios (
    id SERIAL PRIMARY KEY,
    username VARCHAR(80) NOT NULL UNIQUE,
    senha_hash VARCHAR(256) NOT NULL,
    role VARCHAR(20) NOT NULL DEFAULT 'admin',
    ativo BOOLEAN DEFAULT TRUE,
    criado_em TIMESTAMP DEFAULT NOW(),
    ultimo_acesso TIMESTAMP
);

CREATE TABLE IF NOT EXISTS api_keys (
    id SERIAL PRIMARY KEY,
    nome VARCHAR(100) NOT NULL,
    key_hash VARCHAR(256) NOT NULL UNIQUE,
    ativo BOOLEAN DEFAULT TRUE,
    criado_em TIMESTAMP DEFAULT NOW(),
    ultimo_uso TIMESTAMP
);

CREATE TABLE IF NOT EXISTS notificacoes_config (
    id SERIAL PRIMARY KEY,
    tipo VARCHAR(20) NOT NULL,
    destino VARCHAR(300) NOT NULL,
    ativo BOOLEAN DEFAULT TRUE,
    criado_em TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS alertas_consumo (
    id SERIAL PRIMARY KEY,
    cliente_id INTEGER REFERENCES clientes(id) ON DELETE CASCADE,
    limite_gb NUMERIC(10,2) NOT NULL,
    notificar_webhook BOOLEAN DEFAULT TRUE,
    notificar_email BOOLEAN DEFAULT TRUE,
    ativo BOOLEAN DEFAULT TRUE,
    ultimo_alerta_em TIMESTAMP,
    criado_em TIMESTAMP DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS alertas_consumo_cliente ON alertas_consumo (cliente_id);

CREATE TABLE IF NOT EXISTS audit_log (
    id BIGSERIAL PRIMARY KEY,
    ts TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    usuario_id INTEGER REFERENCES usuarios(id) ON DELETE SET NULL,
    usuario_nome VARCHAR(80),
    ip VARCHAR(45),
    action VARCHAR(80) NOT NULL,
    target_type VARCHAR(40),
    target_id VARCHAR(80),
    detail JSONB DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS audit_log_ts      ON audit_log (ts DESC);
CREATE INDEX IF NOT EXISTS audit_log_action  ON audit_log (action);
CREATE INDEX IF NOT EXISTS audit_log_usuario ON audit_log (usuario_id);

CREATE TABLE IF NOT EXISTS alert_state (
    dedup_key VARCHAR(200) PRIMARY KEY,
    event_type VARCHAR(80) NOT NULL,
    severity VARCHAR(20) NOT NULL DEFAULT 'info',
    firing BOOLEAN NOT NULL DEFAULT TRUE,
    primeira_vez TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    ultima_vez TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_sent_at TIMESTAMP WITH TIME ZONE,
    last_msg TEXT,
    count_total INTEGER DEFAULT 0,
    detail JSONB DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS alert_state_firing ON alert_state (firing);
CREATE INDEX IF NOT EXISTS alert_state_event  ON alert_state (event_type);

CREATE TABLE IF NOT EXISTS maintenance_window (
    id SERIAL PRIMARY KEY,
    inicio TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    fim TIMESTAMP WITH TIME ZONE NOT NULL,
    escopo VARCHAR(100) NOT NULL DEFAULT 'all',
    motivo TEXT,
    criado_por VARCHAR(80),
    criado_em TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS maintenance_window_fim ON maintenance_window (fim);

CREATE TABLE IF NOT EXISTS api_key_ips (
    id SERIAL PRIMARY KEY,
    api_key_id INTEGER REFERENCES api_keys(id) ON DELETE CASCADE,
    ip VARCHAR(45) NOT NULL,
    primeira_vez TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    ultima_vez TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE (api_key_id, ip)
);
CREATE INDEX IF NOT EXISTS api_key_ips_lookup ON api_key_ips (api_key_id, ip);

CREATE TABLE IF NOT EXISTS mini_app_users (
    telegram_user_id BIGINT PRIMARY KEY,
    nome VARCHAR(150),
    role VARCHAR(20) DEFAULT 'admin',
    ativo BOOLEAN DEFAULT TRUE,
    criado_em TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    ultimo_acesso TIMESTAMP WITH TIME ZONE
);

-- Tabelas de monitoramento adicionadas durante as fases anteriores
CREATE TABLE IF NOT EXISTS cpe_devices (
    id SERIAL PRIMARY KEY,
    cliente_id INTEGER REFERENCES clientes(id) ON DELETE SET NULL,
    serial_number VARCHAR(150),
    mac_address VARCHAR(20),
    modelo VARCHAR(150),
    fabricante VARCHAR(100),
    genieacs_id VARCHAR(300) UNIQUE,
    ip_wan VARCHAR(50),
    ip_lan VARCHAR(50),
    online BOOLEAN DEFAULT FALSE,
    ultima_conexao TIMESTAMP,
    rx_power FLOAT,
    ssid VARCHAR(100),
    ssid_5g VARCHAR(100),
    ssid_24g VARCHAR(100),
    firmware_version VARCHAR(100),
    uptime_seconds INTEGER DEFAULT 0,
    obs TEXT,
    criado_em TIMESTAMP DEFAULT NOW(),
    atualizado_em TIMESTAMP DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS cpe_devices_cliente_id  ON cpe_devices(cliente_id);
CREATE INDEX IF NOT EXISTS cpe_devices_genieacs_id ON cpe_devices(genieacs_id);
CREATE INDEX IF NOT EXISTS cpe_devices_online      ON cpe_devices(online);

CREATE TABLE IF NOT EXISTS cpe_events (
    id SERIAL PRIMARY KEY,
    cpe_id INTEGER REFERENCES cpe_devices(id) ON DELETE CASCADE,
    event_type VARCHAR(50) NOT NULL,
    detail JSONB DEFAULT '{}',
    criado_em TIMESTAMP DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS cpe_events_cpe_id    ON cpe_events(cpe_id);
CREATE INDEX IF NOT EXISTS cpe_events_tipo      ON cpe_events(event_type);
CREATE INDEX IF NOT EXISTS cpe_events_criado_em ON cpe_events(criado_em DESC);

CREATE TABLE IF NOT EXISTS chamados (
    id SERIAL PRIMARY KEY,
    cpe_id INTEGER REFERENCES cpe_devices(id) ON DELETE SET NULL,
    cliente_id INTEGER REFERENCES clientes(id) ON DELETE SET NULL,
    tipo VARCHAR(50) NOT NULL,
    descricao TEXT,
    status VARCHAR(20) DEFAULT 'aberto',
    criado_em TIMESTAMP DEFAULT NOW(),
    atualizado_em TIMESTAMP DEFAULT NOW(),
    resolvido_em TIMESTAMP
);
CREATE INDEX IF NOT EXISTS chamados_status   ON chamados(status);
CREATE INDEX IF NOT EXISTS chamados_cpe_id   ON chamados(cpe_id);
CREATE INDEX IF NOT EXISTS chamados_cliente  ON chamados(cliente_id);

CREATE TABLE IF NOT EXISTS alertas_config (
    id SERIAL PRIMARY KEY,
    chave VARCHAR(100) NOT NULL UNIQUE,
    valor VARCHAR(200) NOT NULL,
    descricao TEXT,
    atualizado_em TIMESTAMP DEFAULT NOW()
);
"""


def upgrade() -> None:
    op.execute(SCHEMA_SQL)


def downgrade() -> None:
    # Não revertemos a baseline.
    pass
