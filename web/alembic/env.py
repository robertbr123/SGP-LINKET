"""
Alembic environment.

Lê DB_HOST/DB_NAME/DB_USER/DB_PASS do environment (mesmo padrão dos containers).
Não usa autogenerate (sem ORM models) — todas as migrations são manuais e
escritas em SQL puro via op.execute().
"""
import os
from logging.config import fileConfig

from sqlalchemy import engine_from_config, pool
from alembic import context

config = context.config

# Substitui placeholders no sqlalchemy.url
config.set_main_option(
    "sqlalchemy.url",
    f"postgresql://{os.environ.get('DB_USER', 'radius')}:"
    f"{os.environ.get('DB_PASS', 'radiuspassword')}@"
    f"{os.environ.get('DB_HOST', 'postgres')}/"
    f"{os.environ.get('DB_NAME', 'radius')}",
)

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = None


def run_migrations_offline() -> None:
    url = config.get_main_option("sqlalchemy.url")
    context.configure(url=url, target_metadata=target_metadata, literal_binds=True)
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
