-- Tabela de planos
CREATE TABLE IF NOT EXISTS planos (
    id SERIAL PRIMARY KEY,
    nome VARCHAR(100) NOT NULL UNIQUE,
    velocidade_down INTEGER NOT NULL DEFAULT 10,
    velocidade_up INTEGER NOT NULL DEFAULT 5,
    criado_em TIMESTAMP DEFAULT NOW()
);

-- Tabela de pools de IP
CREATE TABLE IF NOT EXISTS pools (
    id SERIAL PRIMARY KEY,
    nome VARCHAR(100) NOT NULL UNIQUE,
    range_inicio VARCHAR(15) NOT NULL,
    range_fim VARCHAR(15) NOT NULL,
    descricao VARCHAR(200),
    criado_em TIMESTAMP DEFAULT NOW()
);

-- Tabela de clientes
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

-- Índice único parcial: pppoe_login só pode repetir se for NULL ou vazio
CREATE UNIQUE INDEX IF NOT EXISTS clientes_pppoe_login_unique
    ON clientes (pppoe_login)
    WHERE pppoe_login IS NOT NULL AND pppoe_login != '';

-- Tabelas nativas do FreeRADIUS
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

-- Índices de performance no radacct (consultas frequentes)
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
    mikrotik_pass VARCHAR(64) DEFAULT ''
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

-- Usuários do painel web
CREATE TABLE IF NOT EXISTS usuarios (
    id SERIAL PRIMARY KEY,
    username VARCHAR(80) NOT NULL UNIQUE,
    senha_hash VARCHAR(256) NOT NULL,
    role VARCHAR(20) NOT NULL DEFAULT 'admin',
    ativo BOOLEAN DEFAULT TRUE,
    criado_em TIMESTAMP DEFAULT NOW(),
    ultimo_acesso TIMESTAMP
);

-- API Keys para acesso REST externo
CREATE TABLE IF NOT EXISTS api_keys (
    id SERIAL PRIMARY KEY,
    nome VARCHAR(100) NOT NULL,
    key_hash VARCHAR(256) NOT NULL UNIQUE,
    ativo BOOLEAN DEFAULT TRUE,
    criado_em TIMESTAMP DEFAULT NOW(),
    ultimo_uso TIMESTAMP
);

-- Configurações de notificações (email / webhook)
CREATE TABLE IF NOT EXISTS notificacoes_config (
    id SERIAL PRIMARY KEY,
    tipo VARCHAR(20) NOT NULL,
    destino VARCHAR(300) NOT NULL,
    ativo BOOLEAN DEFAULT TRUE,
    criado_em TIMESTAMP DEFAULT NOW()
);
