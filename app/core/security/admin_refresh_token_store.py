"""AdminRefreshTokenStore — the RefreshTokenStorePort adapter over admin_refresh_tokens
(jwt-service.md §6.2). A ParticipantSessionStore over participant_sessions arrives in Stage 6,
implementing the same Protocol.
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import update
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.admin_refresh_token import AdminRefreshToken

from .ports import RefreshTokenRecord


def _to_record(row: AdminRefreshToken) -> RefreshTokenRecord:
    return RefreshTokenRecord(
        id=row.id,
        subject_id=row.admin_user_id,
        token_hash=row.token_hash,
        issued_at=row.issued_at,
        expires_at=row.expires_at,
        revoked_at=row.revoked_at,
        replaced_by_id=row.replaced_by_id,
    )


class AdminRefreshTokenStore:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def save(self, record: RefreshTokenRecord) -> None:
        self._session.add(
            AdminRefreshToken(
                id=record.id,
                admin_user_id=record.subject_id,
                token_hash=record.token_hash,
                issued_at=record.issued_at,
                expires_at=record.expires_at,
            )
        )
        await self._session.commit()

    async def find_by_id(self, id: UUID) -> RefreshTokenRecord | None:
        row = await self._session.get(AdminRefreshToken, id)
        return _to_record(row) if row is not None else None

    async def claim_for_rotation(self, id: UUID, *, replaced_by_id: UUID) -> bool:
        """Single atomic UPDATE ... WHERE revoked_at IS NULL — see ports.py for why this has to
        be one statement rather than a locked SELECT followed by a separate UPDATE."""
        result = await self._session.execute(
            update(AdminRefreshToken)
            .where(AdminRefreshToken.id == id, AdminRefreshToken.revoked_at.is_(None))
            .values(revoked_at=datetime.now(UTC), replaced_by_id=replaced_by_id)
        )
        await self._session.commit()
        return result.rowcount > 0

    async def mark_revoked(self, id: UUID, *, replaced_by_id: UUID | None = None) -> None:
        values: dict[str, object] = {"revoked_at": datetime.now(UTC)}
        if replaced_by_id is not None:
            values["replaced_by_id"] = replaced_by_id
        await self._session.execute(
            update(AdminRefreshToken).where(AdminRefreshToken.id == id).values(**values)
        )
        await self._session.commit()

    async def revoke_all_for_subject(self, subject_id: UUID) -> None:
        await self._session.execute(
            update(AdminRefreshToken)
            .where(
                AdminRefreshToken.admin_user_id == subject_id,
                AdminRefreshToken.revoked_at.is_(None),
            )
            .values(revoked_at=datetime.now(UTC))
        )
        await self._session.commit()
