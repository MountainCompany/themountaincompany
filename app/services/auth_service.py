"""AuthService — Stage 2 (docs/IMPLEMENTATION_PLAN.md §5): email lookup, password verify,
token issuance. Business logic lives here, not in the router (BACKEND_REQUIREMENTS.md §1:
"routers stay thin").
"""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security.ports import PasswordHasherPort, TokenPair
from app.core.security.session_service import SessionService
from app.models.admin_user import AdminUser


class InvalidCredentialsError(Exception):
    """Wrong email, wrong password, or an inactive account — deliberately the same error for
    all three so a login response never tells an attacker which one was wrong."""


class AuthService:
    def __init__(
        self,
        session: AsyncSession,
        password_hasher: PasswordHasherPort,
        session_service: SessionService,
    ) -> None:
        self._session = session
        self._password_hasher = password_hasher
        self._session_service = session_service

    async def login(
        self,
        *,
        email: str,
        password: str,
        user_agent: str | None = None,
        ip_address: str | None = None,
    ) -> tuple[TokenPair, AdminUser]:
        result = await self._session.execute(select(AdminUser).where(AdminUser.email == email))
        admin = result.scalar_one_or_none()

        if admin is None or not admin.is_active:
            raise InvalidCredentialsError()

        if not self._password_hasher.verify(password, admin.password_hash):
            raise InvalidCredentialsError()

        if self._password_hasher.needs_rehash(admin.password_hash):
            admin.password_hash = self._password_hasher.hash(password)

        admin.last_login_at = datetime.now(UTC)
        await self._session.commit()

        pair = await self._session_service.issue(
            sub=str(admin.id),
            sub_type="admin",
            role=admin.role.value,
            user_agent=user_agent,
            ip_address=ip_address,
        )
        return pair, admin

    async def refresh(self, refresh_token: str) -> TokenPair:
        return await self._session_service.rotate(refresh_token)

    async def logout(self, refresh_token: str) -> None:
        await self._session_service.revoke(refresh_token)
