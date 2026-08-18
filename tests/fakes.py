"""In-memory RefreshTokenStorePort — lets SessionService's rotation/reuse-detection logic be
unit-tested without a real Postgres. Real correctness of claim_for_rotation's atomicity is
Postgres's job at the SQL level (AdminRefreshTokenStore); what this fake proves is that
SessionService calls the port correctly — i.e. that it can't win a race the store legitimately
lost. The asyncio.Lock here stands in for Postgres's row-level UPDATE locking.

claim_for_rotation also enforces the self-referencing FK that admin_refresh_tokens.replaced_by_id
has in the real schema (migrations/versions/0001_admin_auth.py) — SessionService.rotate() got
this ordering wrong twice before it was caught (see the docstring on rotate() itself), and the
first wrong ordering only surfaced against a real Postgres FK constraint, because this fake
didn't enforce one. It does now, specifically so a regression here fails in the unit suite
instead of only in production against Supabase.
"""

from __future__ import annotations

import asyncio
from dataclasses import replace
from datetime import UTC, datetime
from uuid import UUID

from app.core.security.ports import RefreshTokenRecord


class FakeRefreshTokenStore:
    def __init__(self) -> None:
        self._rows: dict[UUID, RefreshTokenRecord] = {}
        self._lock = asyncio.Lock()

    async def save(self, record: RefreshTokenRecord) -> None:
        self._rows[record.id] = record

    async def find_by_id(self, id: UUID) -> RefreshTokenRecord | None:
        return self._rows.get(id)

    async def claim_for_rotation(self, id: UUID, *, replaced_by_id: UUID) -> bool:
        if replaced_by_id not in self._rows:
            # Mirrors admin_refresh_tokens_replaced_by_id_fkey — a real Postgres INSERT/UPDATE
            # would reject this the same way; ForeignKeyViolationError is asyncpg's actual
            # exception name for it.
            raise ValueError(
                f"claim_for_rotation: replaced_by_id={replaced_by_id} does not reference an "
                "existing row — the new row must be saved() before claiming the old one"
            )
        async with self._lock:
            row = self._rows.get(id)
            await asyncio.sleep(0)  # force a real interleaving point, like a DB round-trip
            if row is None or row.revoked_at is not None:
                return False
            self._rows[id] = replace(
                row, revoked_at=datetime.now(UTC), replaced_by_id=replaced_by_id
            )
            return True

    async def mark_revoked(self, id: UUID, *, replaced_by_id: UUID | None = None) -> None:
        row = self._rows.get(id)
        if row is None:
            return
        self._rows[id] = replace(
            row,
            revoked_at=datetime.now(UTC),
            replaced_by_id=replaced_by_id if replaced_by_id is not None else row.replaced_by_id,
        )

    async def revoke_all_for_subject(self, subject_id: UUID) -> None:
        for id, row in list(self._rows.items()):
            if row.subject_id == subject_id and row.revoked_at is None:
                self._rows[id] = replace(row, revoked_at=datetime.now(UTC))
