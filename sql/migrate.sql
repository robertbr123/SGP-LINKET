-- =============================================================================
-- Migração para banco existente
-- Execute este arquivo se o banco já estava criado antes das novas features
-- =============================================================================

-- Novas colunas na tabela clientes
ALTER TABLE clientes ADD COLUMN IF NOT EXISTS ultimo_sync_em TIMESTAMP;

-- Novas colunas na tabela nas (API MikroTik)
ALTER TABLE nas ADD COLUMN IF NOT EXISTS mikrotik_user VARCHAR(64) DEFAULT 'admin';
ALTER TABLE nas ADD COLUMN IF NOT EXISTS mikrotik_pass VARCHAR(64) DEFAULT '';
ALTER TABLE nas ADD COLUMN IF NOT EXISTS mikrotik_port INTEGER DEFAULT 8728;

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

-- Tabela de alertas de consumo (limites mensais por cliente ou global)
CREATE TABLE IF NOT EXISTS alertas_consumo (
    id SERIAL PRIMARY KEY,
    cliente_id INTEGER REFERENCES clientes(id) ON DELETE CASCADE,
    limite_gb NUMERIC(10,2) NOT NULL,
    notificar_webhook BOOLEAN DEFAULT TRUE,
    notificar_email BOOLEAN DEFAULT TRUE,
    ativo BOOLEAN DEFAULT TRUE,
    criado_em TIMESTAMP DEFAULT NOW()
);

-- Índice para busca por cliente
CREATE INDEX IF NOT EXISTS alertas_consumo_cliente ON alertas_consumo (cliente_id);

-- Coluna para rastrear notificação já enviada no mês corrente
ALTER TABLE alertas_consumo ADD COLUMN IF NOT EXISTS ultimo_alerta_em TIMESTAMP;

-- =============================================================================
-- CPE Devices (GenieACS / TR-069)
-- =============================================================================
CREATE TABLE IF NOT EXISTS cpe_devices (
    id SERIAL PRIMARY KEY,
    cliente_id INTEGER REFERENCES clientes(id) ON DELETE SET NULL,
    serial_number VARCHAR(150),
    mac_address VARCHAR(20),
    modelo VARCHAR(150),
    fabricante VARCHAR(100),
    genieacs_id VARCHAR(300) UNIQUE,        -- ID canônico do GenieACS (OUI-Class-Serial)
    ip_wan VARCHAR(50),
    ip_lan VARCHAR(50),
    online BOOLEAN DEFAULT FALSE,
    ultima_conexao TIMESTAMP,
    rx_power FLOAT,                          -- Potência óptica dBm (ONUs GPON)
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
CREATE INDEX IF NOT EXISTS cpe_devices_online       ON cpe_devices(online);
