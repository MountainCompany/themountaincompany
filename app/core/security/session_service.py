"""SessionService — composes TokenServicePort + RefreshTokenStorePort to implement the rotation
and revocation algorithm from jwt-service.md §2.3-2.4. Deliberately kept out of TokenServicePort
itself (see ports.py) so the token engine stays pure crypto with zero DB dependency; this class
is where "crypto" and "storage" meet, and it's the one thing that does NOT extract cleanly into
a stateless microservice on its own — it would take RefreshTokenStorePort's data (or a client to
wherever that data lives) with it.

One instance serves either subject type — construct it with the store adapter for whichever
table applies (AdminRefreshTokenStore today; a ParticipantSessionStore in Stage 6), same as
jwt-service.md §3.2's "one service, two thin wrappers" framing.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from uuid import UUID

from .exceptions import InvalidTokenError, RefreshReuseDetectedError
from .ports import RefreshTokenRecord, RefreshTokenStorePort, SubType, TokenPair, TokenServicePort


def _hash_token(raw: str) -> str:
    """jwt-service.md §4.3 — store SHA-256(raw_refresh_jwt), never the raw token."""
    return hashlib.sha256(raw.encode()).hexdigest()


class SessionService:
    def __init__(self, token_service: TokenServicePort, store: RefreshTokenStorePort) -> None:
        self._token_service = token_service
        self._store = store

    async def issue(
        self,
        *,
        sub: str,
        sub_type: SubType,
        role: str,
        user_agent: str | None = None,
        ip_address: str | None = None,
    ) -> TokenPair:
        """New login — mints a pair and persists the refresh token's revocation record."""
        pair = self._token_service.issue_pair(sub=sub, sub_type=sub_type, role=role)
        await self._store.save(
            RefreshTokenRecord(
                id=UUID(pair.refresh_jti),
                subject_id=UUID(sub),
                token_hash=_hash_token(pair.refresh_token),
                issued_at=datetime.now(UTC),
                expires_at=pair.refresh_expires_at,
                revoked_at=None,
                replaced_by_id=None,
            )
        )
        # user_agent/ip_address land in the token-table row via the store adapter in a future
        # pass — RefreshTokenRecord doesn't carry them yet since nothing consumes them until
        # Stage 2's login endpoint has a real request to read them from.
        return pair

    async def rotate(self, refresh_token: str) -> TokenPair:
        """jwt-service.md §2.3. Raises InvalidTokenError if the token doesn't decode or doesn't
        match a known row, RefreshReuseDetectedError if it's already been rotated/revoked, or if
        it loses a race to a concurrent rotate() call on the same token (§8.1's concurrency
        test — exactly one of two simultaneous callers may win). Either way, every session for
        that subject has just been revoked as a side effect by the time this raises — including,
        in the race-loss case, the "winning" caller's brand-new row, which is what actually
        enforces "force re-login" rather than quietly trusting one of two racing requests.

        Ordering here has already broken twice in earlier drafts, both invisible until tested
        against a real Postgres FK constraint (the in-memory test fake doesn't enforce one):

        1. First draft called self.issue() (commits) before revoking the old row — released the
           old row's lock too early and let two concurrent callers both win.
        2. Second draft fixed that by claiming (revoking) the old row before inserting the new
           one — but admin_refresh_tokens.replaced_by_id is a self-referencing FK, and pointing
           the old row at a new row that doesn't exist yet violates it.

        Correct order: insert the new row first (its own id is a fresh uuid4, no conflict
        possible), *then* atomically claim the old row and point its replaced_by_id at the row
        that now actually exists. The atomic claim — not the insert ordering — is what still
        provides the race-safety guarantee from fix #1: two concurrent claims on the same old
        row still can't both win, because claim_for_rotation's UPDATE ... WHERE revoked_at IS
        NULL only ever matches for the first one to commit.
        """
        claims = self._token_service.decode_token(refresh_token, expected_type="refresh")
        old_id = UUID(claims.jti)

        old_record = await self._store.find_by_id(old_id)
        if old_record is None or old_record.token_hash != _hash_token(refresh_token):
            raise InvalidTokenError("refresh token not recognized")

        if old_record.revoked_at is not None:
            await self._store.revoke_all_for_subject(old_record.subject_id)
            raise RefreshReuseDetectedError(subject_id=old_record.subject_id)

        new_pair = self._token_service.issue_pair(sub=claims.sub, sub_type=claims.sub_type, role=claims.role)

        await self._store.save(
            RefreshTokenRecord(
                id=UUID(new_pair.refresh_jti),
                subject_id=old_record.subject_id,
                token_hash=_hash_token(new_pair.refresh_token),
                issued_at=datetime.now(UTC),
                expires_at=new_pair.refresh_expires_at,
                revoked_at=None,
                replaced_by_id=None,
            )
        )

        won = await self._store.claim_for_rotation(old_id, replaced_by_id=UUID(new_pair.refresh_jti))
        if not won:
            # Lost the race (or the old row was revoked by something else in between). The new
            # row just inserted above is now an orphan for this subject — revoke_all_for_subject
            # below sweeps it up along with everything else, so nothing live is left behind.
            await self._store.revoke_all_for_subject(old_record.subject_id)
            raise RefreshReuseDetectedError(subject_id=old_record.subject_id)

        return new_pair

    async def revoke(self, refresh_token: str) -> None:
        """Logout — revokes exactly the presented refresh token (jwt-service.md §2.4)."""
        claims = self._token_service.decode_token(refresh_token, expected_type="refresh")
        await self._store.mark_revoked(UUID(claims.jti))

    async def revoke_all(self, subject_id: UUID) -> None:
        """Logout all devices — password change, or reuse detected elsewhere (§2.4)."""
        await self._store.revoke_all_for_subject(subject_id)
