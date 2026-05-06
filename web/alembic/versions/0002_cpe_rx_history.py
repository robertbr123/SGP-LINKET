"""cpe rx history para predição de falhas

Revision ID: 0002
Revises: 0001
Create Date: 2026-05-06
"""
from alembic import op


revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(r"""
        CREATE TABLE IF NOT EXISTS cpe_rx_history (
            id BIGSERIAL PRIMARY KEY,
            cpe_id INTEGER NOT NULL REFERENCES cpe_devices(id) ON DELETE CASCADE,
            rx_power FLOAT NOT NULL,
            criado_em TIMESTAMP WITH TIME ZONE DEFAULT NOW()
        );
        CREATE INDEX IF NOT EXISTS cpe_rx_history_cpe_ts
            ON cpe_rx_history (cpe_id, criado_em DESC);

        -- Auto-cleanup: mantém só 30 dias
        -- (uma versão futura pode adicionar pg_cron pra rodar isso periodicamente)
    """)


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS cpe_rx_history")
