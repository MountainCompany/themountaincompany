"""jwt-service.md §8.1 test checklist — refresh rotation, reuse detection, logout revokes
exactly one row, and the concurrency case: two simultaneous refresh calls on the same token,
exactly one succeeds.
"""

from __future__ import annotations

import asyncio
import uuid

import pytest

from app.core.security.exceptions import InvalidTokenError, RefreshReuseDetectedError
from app.core.security.jwt_service import JWTTokenService
from app.core.security.ports import TokenPair
from app.core.security.session_service import SessionService

from .fakes import FakeRefreshTokenStore

SECRET = "test-secret-key-not-for-real-use"
SUBJECT = str(uuid.uuid4())


@pytest.fixture
def session_service() -> SessionService:
    return SessionService(JWTTokenService(secret_key=SECRET), FakeRefreshTokenStore())


async def test_issue_persists_a_matching_refresh_row(session_service: SessionService) -> None:
    pair = await session_service.issue(sub=SUBJECT, sub_type="admin", role="owner")
    store: FakeRefreshTokenStore = session_service._store  # type: ignore[attr-defined]

    record = await store.find_by_id(uuid.UUID(pair.refresh_jti))
    assert record is not None
    assert str(record.subject_id) == SUBJECT
    assert record.revoked_at is None


async def test_rotate_returns_a_new_pair_and_revokes_the_old_row(session_service: SessionService) -> None:
    old_pair = await session_service.issue(sub=SUBJECT, sub_type="admin", role="owner")
    new_pair = await session_service.rotate(old_pair.refresh_token)
    store: FakeRefreshTokenStore = session_service._store  # type: ignore[attr-defined]

    assert new_pair.refresh_jti != old_pair.refresh_jti

    old_record = await store.find_by_id(uuid.UUID(old_pair.refresh_jti))
    assert old_record is not None
    assert old_record.revoked_at is not None
    assert old_record.replaced_by_id == uuid.UUID(new_pair.refresh_jti)

    new_record = await store.find_by_id(uuid.UUID(new_pair.refresh_jti))
    assert new_record is not None
    assert new_record.revoked_at is None


async def test_reusing_an_already_rotated_token_is_detected_and_revokes_everything(
    session_service: SessionService,
) -> None:
    old_pair = await session_service.issue(sub=SUBJECT, sub_type="admin", role="owner")
    new_pair = await session_service.rotate(old_pair.refresh_token)  # rotates old_pair away

    with pytest.raises(RefreshReuseDetectedError) as exc_info:
        await session_service.rotate(old_pair.refresh_token)  # reuse of the now-dead token
    assert str(exc_info.value.subject_id) == SUBJECT

    # Reuse revokes the *entire* chain, including the token that was legitimately issued by
    # the rotation in between — jwt-service.md §2.3: "revoke the entire chain."
    store: FakeRefreshTokenStore = session_service._store  # type: ignore[attr-defined]
    new_record = await store.find_by_id(uuid.UUID(new_pair.refresh_jti))
    assert new_record is not None
    assert new_record.revoked_at is not None


async def test_rotate_rejects_a_refresh_token_with_no_matching_row(session_service: SessionService) -> None:
    forged = SessionService(JWTTokenService(secret_key=SECRET), FakeRefreshTokenStore())
    pair = forged._token_service.issue_pair(sub=SUBJECT, sub_type="admin", role="owner")  # never saved

    with pytest.raises(InvalidTokenError):
        await session_service.rotate(pair.refresh_token)


async def test_revoke_revokes_exactly_one_session_not_others(session_service: SessionService) -> None:
    pair_a = await session_service.issue(sub=SUBJECT, sub_type="admin", role="owner")
    pair_b = await session_service.issue(sub=SUBJECT, sub_type="admin", role="owner")

    await session_service.revoke(pair_a.refresh_token)

    store: FakeRefreshTokenStore = session_service._store  # type: ignore[attr-defined]
    record_a = await store.find_by_id(uuid.UUID(pair_a.refresh_jti))
    record_b = await store.find_by_id(uuid.UUID(pair_b.refresh_jti))
    assert record_a is not None and record_a.revoked_at is not None
    assert record_b is not None and record_b.revoked_at is None

    # The untouched session still rotates fine.
    await session_service.rotate(pair_b.refresh_token)


async def test_revoke_all_revokes_every_active_session_for_the_subject(
    session_service: SessionService,
) -> None:
    pair_a = await session_service.issue(sub=SUBJECT, sub_type="admin", role="owner")
    pair_b = await session_service.issue(sub=SUBJECT, sub_type="admin", role="owner")

    await session_service.revoke_all(uuid.UUID(SUBJECT))

    store: FakeRefreshTokenStore = session_service._store  # type: ignore[attr-defined]
    for pair in (pair_a, pair_b):
        record = await store.find_by_id(uuid.UUID(pair.refresh_jti))
        assert record is not None
        assert record.revoked_at is not None


async def test_concurrent_rotation_of_the_same_token_exactly_one_wins(
    session_service: SessionService,
) -> None:
    pair = await session_service.issue(sub=SUBJECT, sub_type="admin", role="owner")

    results = await asyncio.gather(
        session_service.rotate(pair.refresh_token),
        session_service.rotate(pair.refresh_token),
        return_exceptions=True,
    )

    successes = [r for r in results if isinstance(r, TokenPair)]
    reuse_errors = [r for r in results if isinstance(r, RefreshReuseDetectedError)]

    assert len(successes) == 1, f"expected exactly one winner, got: {results!r}"
    assert len(reuse_errors) == 1

    # The loser's reuse detection revoked everything, including the winner's brand-new token.
    store: FakeRefreshTokenStore = session_service._store  # type: ignore[attr-defined]
    winner_record = await store.find_by_id(uuid.UUID(successes[0].refresh_jti))
    assert winner_record is not None
    assert winner_record.revoked_at is not None
