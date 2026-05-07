"""ai features extra: chamados ai_categoria/ai_sugestao + anomalia consumo

Revision ID: 0004
Revises: 0003
Create Date: 2026-05-06
"""
from alembic import op


revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(r"""
        ALTER TABLE chamados ADD COLUMN IF NOT EXISTS ai_categoria VARCHAR(60);
        ALTER TABLE chamados ADD COLUMN IF NOT EXISTS ai_sugestao TEXT;
        ALTER TABLE chamados ADD COLUMN IF NOT EXISTS ai_classificado_em TIMESTAMP WITH TIME ZONE;

        CREATE INDEX IF NOT EXISTS chamados_ai_categoria ON chamados (ai_categoria);

        -- Snapshot de fraude para histórico/UI (não precisa rodar IA pra cada page load)
        CREATE TABLE IF NOT EXISTS consumo_anomalias (
            id SERIAL PRIMARY KEY,
            cliente_id INTEGER REFERENCES clientes(id) ON DELETE CASCADE,
            detectado_em TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
            consumo_atual_gb NUMERIC(10,2),
            media_30d_gb NUMERIC(10,2),
            stddev_gb NUMERIC(10,2),
            zscore NUMERIC(10,2),
            severidade VARCHAR(20) DEFAULT 'warning',
            ignorado BOOLEAN DEFAULT FALSE,
            ignorado_em TIMESTAMP WITH TIME ZONE,
            ignorado_por VARCHAR(80)
        );
        CREATE INDEX IF NOT EXISTS consumo_anomalias_cliente ON consumo_anomalias (cliente_id);
        CREATE INDEX IF NOT EXISTS consumo_anomalias_detectado ON consumo_anomalias (detectado_em DESC);
        CREATE INDEX IF NOT EXISTS consumo_anomalias_pendentes ON consumo_anomalias (ignorado) WHERE ignorado = FALSE;

        INSERT INTO alertas_config (chave, valor, descricao) VALUES
            ('anomalia_zscore_min', '3.0', 'Z-score mínimo pra considerar anomalia (3.0 = 3 desvios padrão)')
        ON CONFLICT (chave) DO NOTHING;
        INSERT INTO alertas_config (chave, valor, descricao) VALUES
            ('anomalia_consumo_min_gb', '20', 'Consumo mínimo (GB) para considerar anomalia (evita ruído de clientes leves)')
        ON CONFLICT (chave) DO NOTHING;
    """)


def downgrade() -> None:
    op.execute("""
        DROP TABLE IF EXISTS consumo_anomalias;
        ALTER TABLE chamados DROP COLUMN IF EXISTS ai_categoria;
        ALTER TABLE chamados DROP COLUMN IF EXISTS ai_sugestao;
        ALTER TABLE chamados DROP COLUMN IF EXISTS ai_classificado_em;
    """)
