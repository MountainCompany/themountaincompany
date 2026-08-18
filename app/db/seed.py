"""jwt-service.md §9.1 — the first `owner` admin account is seeded, not migrated: a hardcoded
email/password in a migration file would sit in git history in plaintext forever. This runs
on deploy (or as a one-off command) instead, and is safe to run every time — it's a no-op once
an owner already exists.

Usage:
    python -m app.db.seed
"""

from __future__ import annotations

import asyncio
import logging

from sqlalchemy import select

from app.core.config import get_settings
from app.core.security.password_hasher import Argon2PasswordHasher
from app.db.base import get_session_factory
from app.models.admin_user import AdminRole, AdminUser

logger = logging.getLogger(__name__)


async def seed_first_owner() -> None:
    settings = get_settings()
    session_factory = get_session_factory()

    async with session_factory() as session:
        existing = await session.execute(select(AdminUser).where(AdminUser.role == AdminRole.owner))
        if existing.scalar_one_or_none() is not None:
            logger.info("seed: an owner admin already exists — nothing to do")
            return

        if not settings.INITIAL_ADMIN_EMAIL or not settings.INITIAL_ADMIN_PASSWORD:
            raise RuntimeError(
                "INITIAL_ADMIN_EMAIL and INITIAL_ADMIN_PASSWORD must be set to seed the first "
                "owner account — see .env.example"
            )

        hasher = Argon2PasswordHasher()
        admin = AdminUser(
            email=settings.INITIAL_ADMIN_EMAIL,
            password_hash=hasher.hash(settings.INITIAL_ADMIN_PASSWORD),
            name="Owner",
            role=AdminRole.owner,
        )
        session.add(admin)
        await session.commit()

        logger.warning(
            "seed: created first owner admin (%s) — rotate this password after first login",
            settings.INITIAL_ADMIN_EMAIL,
        )


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    asyncio.run(seed_first_owner())
