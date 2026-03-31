-- =============================================================================
-- Migração para banco existente
-- Execute este arquivo se o banco já estava criado antes das novas features
-- =============================================================================

-- Novas colunas na tabela clientes
ALTER TABLE clientes ADD COLUMN IF NOT EXISTS ultimo_sync_em TIMESTAMP;

-- Novas colunas na tabela nas (API MikroTik)
ALTER TABLE nas ADD COLUMN IF NOT EXISTS mikrotik_user VARCHAR(64) DEFAULT 'admin';
ALTER TABLE nas ADD COLUMN IF NOT EXISTS mikrotik_pass VARCHAR(64) DEFAULT '';

-- Índice único para pppoe_login (evita duplicatas silenciosas)
CREATE UNIQUE INDEX IF NOT EXISTS clientes_pppoe_login_unique
    ON clientes (pppoe_login)
    WHERE pppoe_login IS NOT NULL AND pppoe_login != '';

-- Índices de performance no radacct
CREATE INDEX IF NOT EXISTS radacct_username_stoptime ON radacct (username, acctstoptime);
CREATE INDEX IF NOT EXISTS radacct_username        ON radacct (username);
CREATE INDEX IF NOT EXISTS radacct_nasipaddress    ON radacct (nasipaddress);
CREATE INDEX IF NOT EXISTS radacct_starttime       ON radacct (acctstarttime DESC);
CREATE INDEX IF NOT EXISTS radacct_stoptime        ON radacct (acctstoptime);

-- Índices no radpostauth
CREATE INDEX IF NOT EXISTS radpostauth_username ON radpostauth (username);
CREATE INDEX IF NOT EXISTS radpostauth_authdate ON radpostauth (authdate DESC);

-- Tabela de usuários do painel web
CREATE TABLE IF NOT EXISTS usuarios (
    id SERIAL PRIMARY KEY,
    username VARCHAR(80) NOT NULL UNIQUE,
    senha_hash VARCHAR(256) NOT NULL,
    role VARCHAR(20) NOT NULL DEFAULT 'admin',
    ativo BOOLEAN DEFAULT TRUE,
    criado_em TIMESTAMP DEFAULT NOW(),
    ultimo_acesso TIMESTAMP
);

-- Tabela de API Keys
CREATE TABLE IF NOT EXISTS api_keys (
    id SERIAL PRIMARY KEY,
    nome VARCHAR(100) NOT NULL,
    key_hash VARCHAR(256) NOT NULL UNIQUE,
    ativo BOOLEAN DEFAULT TRUE,
    criado_em TIMESTAMP DEFAULT NOW(),
    ultimo_uso TIMESTAMP
);

-- Tabela de notificações
CREATE TABLE IF NOT EXISTS notificacoes_config (
    id SERIAL PRIMARY KEY,
    tipo VARCHAR(20) NOT NULL,
    destino VARCHAR(300) NOT NULL,
    ativo BOOLEAN DEFAULT TRUE,
    criado_em TIMESTAMP DEFAULT NOW()
);
