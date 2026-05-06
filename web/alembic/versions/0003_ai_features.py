"""ai features: github webhook secret + zelador noturno config

Revision ID: 0003
Revises: 0002
Create Date: 2026-05-06
"""
from alembic import op


revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(r"""
        INSERT INTO alertas_config (chave, valor, descricao) VALUES
            ('github_webhook_secret', '', 'Secret HMAC do webhook GitHub para release notes')
        ON CONFLICT (chave) DO NOTHING;
        INSERT INTO alertas_config (chave, valor, descricao) VALUES
            ('zelador_noturno_enabled', 'false', 'Ativar IA pra decidir alertas noturnos (true/false)')
        ON CONFLICT (chave) DO NOTHING;
        INSERT INTO alertas_config (chave, valor, descricao) VALUES
            ('zelador_inicio', '22:00', 'Início do horário noturno (HH:MM)')
        ON CONFLICT (chave) DO NOTHING;
        INSERT INTO alertas_config (chave, valor, descricao) VALUES
            ('zelador_fim', '07:00', 'Fim do horário noturno (HH:MM)')
        ON CONFLICT (chave) DO NOTHING;

        ALTER TABLE alert_state ADD COLUMN IF NOT EXISTS deferred BOOLEAN DEFAULT FALSE;
        ALTER TABLE alert_state ADD COLUMN IF NOT EXISTS deferred_until TIMESTAMP WITH TIME ZONE;
        CREATE INDEX IF NOT EXISTS alert_state_deferred ON alert_state (deferred);
    """)


def downgrade() -> None:
    op.execute("""
        ALTER TABLE alert_state DROP COLUMN IF EXISTS deferred;
        ALTER TABLE alert_state DROP COLUMN IF EXISTS deferred_until;
    """)
