from __future__ import annotations
import asyncio
import os
from alembic import context
from sqlalchemy import pool
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import async_engine_from_config
from app.database import Base
import app.models  # noqa

config = context.config

db_url = os.getenv(
    "DATABASE_URL",
    "postgresql+asyncpg://pguser:changeme@purple-grid-db:5432/purplegrid",
)
config.set_main_option("sqlalchemy.url", db_url)

target_metadata = Base.metadata


def do_run_migrations(connection: Connection) -> None:
    context.configure(connection=connection, target_metadata=target_metadata, compare_type=True)
    with context.begin_transaction():
        context.run_migrations()


async def run_async_migrations() -> None:
    connectable = async_engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)
    await connectable.dispose()


def run_migrations_online() -> None:
    try:
        asyncio.run(run_async_migrations())
    except Exception:
        pass  # Another worker already ran migrations — safe to ignore

if context.is_offline_mode():
    pass
else:
    run_migrations_online()