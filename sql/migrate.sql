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

-- =============================================================================
-- CPE Events — histórico de eventos do equipamento (offline/online/reboot/IP)
-- =============================================================================
CREATE TABLE IF NOT EXISTS cpe_events (
    id SERIAL PRIMARY KEY,
    cpe_id INTEGER REFERENCES cpe_devices(id) ON DELETE CASCADE,
    event_type VARCHAR(50) NOT NULL,   -- online, offline, reboot, ip_change, rx_alert, firmware_update
    detail JSONB DEFAULT '{}',         -- dados extras: ip_anterior, ip_novo, rx_power, etc.
    criado_em TIMESTAMP DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS cpe_events_cpe_id    ON cpe_events(cpe_id);
CREATE INDEX IF NOT EXISTS cpe_events_tipo      ON cpe_events(event_type);
CREATE INDEX IF NOT EXISTS cpe_events_criado_em ON cpe_events(criado_em DESC);

-- =============================================================================
-- Chamados — escalada automática de incidentes
-- =============================================================================
CREATE TABLE IF NOT EXISTS chamados (
    id SERIAL PRIMARY KEY,
    cpe_id INTEGER REFERENCES cpe_devices(id) ON DELETE SET NULL,
    cliente_id INTEGER REFERENCES clientes(id) ON DELETE SET NULL,
    tipo VARCHAR(50) NOT NULL,         -- cpe_offline, rx_critico, sem_conexao
    descricao TEXT,
    status VARCHAR(20) DEFAULT 'aberto',  -- aberto, em_atendimento, resolvido
    criado_em TIMESTAMP DEFAULT NOW(),
    atualizado_em TIMESTAMP DEFAULT NOW(),
    resolvido_em TIMESTAMP
);
CREATE INDEX IF NOT EXISTS chamados_status    ON chamados(status);
CREATE INDEX IF NOT EXISTS chamados_cpe_id   ON chamados(cpe_id);
CREATE INDEX IF NOT EXISTS chamados_cliente  ON chamados(cliente_id);

-- Configuração de alertas Telegram/notificações
ALTER TABLE notificacoes_config ADD COLUMN IF NOT EXISTS eventos VARCHAR(300) DEFAULT 'status_change';
-- Ex: 'status_change,cpe_offline,rx_alert,sem_conexao'

-- Thresholds para alertas de Rx Power e CPE offline
CREATE TABLE IF NOT EXISTS alertas_config (
    id SERIAL PRIMARY KEY,
    chave VARCHAR(100) NOT NULL UNIQUE,  -- rx_power_min, cpe_offline_minutos, etc.
    valor VARCHAR(200) NOT NULL,
    descricao TEXT,
    atualizado_em TIMESTAMP DEFAULT NOW()
);
INSERT INTO alertas_config (chave, valor, descricao) VALUES
    ('rx_power_min',      '-27',  'Limiar mínimo de Rx Power em dBm para alerta')
ON CONFLICT (chave) DO NOTHING;
INSERT INTO alertas_config (chave, valor, descricao) VALUES
    ('cpe_offline_minutos', '15', 'Minutos offline para abrir chamado automático')
ON CONFLICT (chave) DO NOTHING;
INSERT INTO alertas_config (chave, valor, descricao) VALUES
    ('telegram_enabled',  'false', 'Ativar alertas Telegram (true/false)')
ON CONFLICT (chave) DO NOTHING;
INSERT INTO alertas_config (chave, valor, descricao) VALUES
    ('telegram_bot_token', '', 'Token do bot Telegram')
ON CONFLICT (chave) DO NOTHING;
INSERT INTO alertas_config (chave, valor, descricao) VALUES
    ('telegram_chat_id',   '', 'Chat ID do grupo/canal Telegram')
ON CONFLICT (chave) DO NOTHING;

-- =============================================================================
-- Sistema de alertas Telegram — Fase 0 (fundação)
-- =============================================================================

-- Auditoria: tudo que importa rastrear (login, ações destrutivas, mudança de senha)
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

-- Estado de alertas firing/resolved (anti-flood + "voltou ao normal")
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

-- Janelas de manutenção (silencia alertas)
-- escopo = 'all' | 'event:cpe_offline' | 'nas:5' | 'cpe:12'
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

-- IPs conhecidos por API key (alerta quando vê IP novo)
CREATE TABLE IF NOT EXISTS api_key_ips (
    id SERIAL PRIMARY KEY,
    api_key_id INTEGER REFERENCES api_keys(id) ON DELETE CASCADE,
    ip VARCHAR(45) NOT NULL,
    primeira_vez TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    ultima_vez TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE (api_key_id, ip)
);
CREATE INDEX IF NOT EXISTS api_key_ips_lookup ON api_key_ips (api_key_id, ip);

-- Configurações novas (limiares e horários)
INSERT INTO alertas_config (chave, valor, descricao) VALUES
    ('alertas_heartbeat_hora',       '09:00', 'Hora do heartbeat diário (HH:MM, vazio = desativado)')
ON CONFLICT (chave) DO NOTHING;
INSERT INTO alertas_config (chave, valor, descricao) VALUES
    ('alertas_resumo_matinal_hora',  '08:00', 'Hora do resumo matinal (HH:MM, vazio = desativado)')
ON CONFLICT (chave) DO NOTHING;
INSERT INTO alertas_config (chave, valor, descricao) VALUES
    ('alertas_resumo_turno_hora',    '18:00', 'Hora do resumo de fim de turno (HH:MM, vazio = desativado)')
ON CONFLICT (chave) DO NOTHING;
INSERT INTO alertas_config (chave, valor, descricao) VALUES
    ('alertas_brute_force_max',      '3',     'Tentativas de login falhadas em 1 min do mesmo IP para alerta')
ON CONFLICT (chave) DO NOTHING;
INSERT INTO alertas_config (chave, valor, descricao) VALUES
    ('alertas_nas_cpu_pct',          '85',    'CPU MikroTik (%) — alerta se ultrapassar')
ON CONFLICT (chave) DO NOTHING;
INSERT INTO alertas_config (chave, valor, descricao) VALUES
    ('alertas_nas_mem_pct',          '85',    'Memória MikroTik (%) — alerta se ultrapassar')
ON CONFLICT (chave) DO NOTHING;
INSERT INTO alertas_config (chave, valor, descricao) VALUES
    ('alertas_nas_temp_c',           '70',    'Temperatura MikroTik (°C) — alerta se ultrapassar')
ON CONFLICT (chave) DO NOTHING;
INSERT INTO alertas_config (chave, valor, descricao) VALUES
    ('alertas_pppoe_zumbi_horas',    '12',    'Sessão PPPoE sem update há X horas = zumbi')
ON CONFLICT (chave) DO NOTHING;
INSERT INTO alertas_config (chave, valor, descricao) VALUES
    ('alertas_sync_travado_min',     '15',    'Minutos sem ciclo do sync para alerta')
ON CONFLICT (chave) DO NOTHING;
