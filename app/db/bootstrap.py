"""Startup schema bootstrap — jwt-service.md §7.5.

Dev: AUTO_MIGRATE=false, this is a no-op. Migrations are applied by hand with
`alembic upgrade head` against the dev DB, same as every other model in the project.

Prod: AUTO_MIGRATE=true. On a fresh database this runs the full Alembic chain to head, guarded
by a Postgres advisory lock so that if prod boots multiple replicas/workers concurrently, only
one of them actually migrates — the rest block briefly on the lock, then see the schema is
already current and return immediately. On every boot after the first, a fast-path check against
`alembic_version` means this costs one cheap query, not a full migration run.

Synchronous by design (Alembic's `command.upgrade` is sync) — called via `asyncio.to_thread`
from the FastAPI lifespan in app/main.py so it doesn't block the event loop.
"""

from __future__ import annotations

import logging
import time

from alembic import command
from alembic.config import Config
from alembic.runtime.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy import create_engine, text

from app.core.config import Settings

logger = logging.getLogger(__name__)

# Arbitrary fixed key, stable across boots/deploys — identifies this lock among any others the
# app might take later. Postgres advisory locks are just int64s with no inherent meaning.
JWT_SCHEMA_LOCK_KEY = 0x4A57545F

_REPO_ROOT = None  # set lazily below to avoid an import-time filesystem walk in tests


def _alembic_config(settings: Settings) -> Config:
    global _REPO_ROOT
    if _REPO_ROOT is None:
        from pathlib import Path

        _REPO_ROOT = Path(__file__).resolve().parents[2]
    cfg = Config(str(_REPO_ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(_REPO_ROOT / "migrations"))
    cfg.set_main_option("sqlalchemy.url", settings.database_url_sync)
    return cfg


def _head_revision(cfg: Config) -> str | None:
    return ScriptDirectory.from_config(cfg).get_current_head()


def _current_revision(conn) -> str | None:
    return MigrationContext.configure(conn).get_current_revision()


def run_startup_migrations(settings: Settings) -> None:
    if not settings.AUTO_MIGRATE:
        return

    cfg = _alembic_config(settings)
    engine = create_engine(settings.database_url_sync)
    try:
        with engine.connect() as conn:
            head = _head_revision(cfg)

            # Fast path — near-zero cost on every boot after the first.
            if _current_revision(conn) == head:
                return

            conn.execute(text("SELECT pg_advisory_lock(:key)"), {"key": JWT_SCHEMA_LOCK_KEY})
            try:
                # Re-check: another instance may have migrated while we waited for the lock.
                if _current_revision(conn) != head:
                    t0 = time.monotonic()
                    command.upgrade(cfg, "head")
                    logger.info(
                        "schema bootstrap: migrated to head",
                        extra={"revision": head, "elapsed_s": round(time.monotonic() - t0, 3)},
                    )
            finally:
                conn.execute(text("SELECT pg_advisory_unlock(:key)"), {"key": JWT_SCHEMA_LOCK_KEY})
    finally:
        engine.dispose()
