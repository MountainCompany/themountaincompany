"""jwt-service.md §8.1 test checklist — jwt_service: encode/decode round-trip, expired token
rejected, tampered signature rejected, wrong typ rejected, secret-rotation fallback.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from jose import jwt

from app.core.security.exceptions import ExpiredTokenError, InvalidTokenError, WrongTokenTypeError
from app.core.security.jwt_service import ALGORITHM, ISSUER, JWTTokenService

SECRET = "test-secret-key-not-for-real-use"
PREVIOUS_SECRET = "old-test-secret-key"


@pytest.fixture
def service() -> JWTTokenService:
    return JWTTokenService(secret_key=SECRET)


def test_issue_pair_round_trips_through_decode(service: JWTTokenService) -> None:
    pair = service.issue_pair(sub="11111111-1111-1111-1111-111111111111", sub_type="admin", role="owner")

    access_claims = service.decode_token(pair.access_token, expected_type="access")
    refresh_claims = service.decode_token(pair.refresh_token, expected_type="refresh")

    assert access_claims.sub == "11111111-1111-1111-1111-111111111111"
    assert access_claims.sub_type == "admin"
    assert access_claims.role == "owner"
    assert access_claims.typ == "access"
    assert access_claims.iss == ISSUER

    assert refresh_claims.typ == "refresh"
    assert refresh_claims.jti == pair.refresh_jti


def test_refresh_jti_is_a_fresh_uuid_each_time(service: JWTTokenService) -> None:
    pair1 = service.issue_pair(sub="s1", sub_type="admin", role="owner")
    pair2 = service.issue_pair(sub="s1", sub_type="admin", role="owner")
    assert pair1.refresh_jti != pair2.refresh_jti


def test_admin_vs_participant_refresh_ttl_differs(service: JWTTokenService) -> None:
    admin_pair = service.issue_pair(sub="s1", sub_type="admin", role="owner")
    participant_pair = service.issue_pair(sub="s2", sub_type="participant", role="self")

    admin_ttl = admin_pair.refresh_expires_at - datetime.now(UTC)
    participant_ttl = participant_pair.refresh_expires_at - datetime.now(UTC)

    assert timedelta(days=6) < admin_ttl < timedelta(days=8)
    assert timedelta(days=29) < participant_ttl < timedelta(days=31)


def test_expired_token_rejected(service: JWTTokenService) -> None:
    now = datetime.now(UTC)
    stale = jwt.encode(
        {
            "sub": "s1", "sub_type": "admin", "typ": "access", "role": "owner", "jti": "j1",
            "iat": int((now - timedelta(minutes=30)).timestamp()),
            "exp": int((now - timedelta(minutes=15)).timestamp()),
            "iss": ISSUER,
        },
        SECRET,
        algorithm=ALGORITHM,
    )
    with pytest.raises(ExpiredTokenError):
        service.decode_token(stale, expected_type="access")


def test_tampered_signature_rejected(service: JWTTokenService) -> None:
    pair = service.issue_pair(sub="s1", sub_type="admin", role="owner")
    header, payload, signature = pair.access_token.split(".")
    tampered_signature = ("A" if signature[0] != "A" else "B") + signature[1:]
    tampered = f"{header}.{payload}.{tampered_signature}"

    with pytest.raises(InvalidTokenError):
        service.decode_token(tampered, expected_type="access")


def test_signed_with_unknown_key_rejected(service: JWTTokenService) -> None:
    foreign = jwt.encode(
        {
            "sub": "s1", "sub_type": "admin", "typ": "access", "role": "owner", "jti": "j1",
            "iat": int(datetime.now(UTC).timestamp()),
            "exp": int((datetime.now(UTC) + timedelta(minutes=15)).timestamp()),
            "iss": ISSUER,
        },
        "a-completely-different-secret",
        algorithm=ALGORITHM,
    )
    with pytest.raises(InvalidTokenError):
        service.decode_token(foreign, expected_type="access")


def test_wrong_type_rejected_access_presented_as_refresh(service: JWTTokenService) -> None:
    pair = service.issue_pair(sub="s1", sub_type="admin", role="owner")
    with pytest.raises(WrongTokenTypeError):
        service.decode_token(pair.access_token, expected_type="refresh")


def test_wrong_type_rejected_refresh_presented_as_access(service: JWTTokenService) -> None:
    pair = service.issue_pair(sub="s1", sub_type="admin", role="owner")
    with pytest.raises(WrongTokenTypeError):
        service.decode_token(pair.refresh_token, expected_type="access")


def test_previous_secret_key_accepted_during_rotation_window() -> None:
    old_service = JWTTokenService(secret_key=PREVIOUS_SECRET)
    pair = old_service.issue_pair(sub="s1", sub_type="admin", role="owner")

    # New service signs with SECRET but still verifies tokens signed under the old key.
    rotated_service = JWTTokenService(secret_key=SECRET, previous_secret_key=PREVIOUS_SECRET)
    claims = rotated_service.decode_token(pair.access_token, expected_type="access")
    assert claims.sub == "s1"


def test_new_tokens_always_sign_with_current_key_not_previous() -> None:
    rotated_service = JWTTokenService(secret_key=SECRET, previous_secret_key=PREVIOUS_SECRET)
    pair = rotated_service.issue_pair(sub="s1", sub_type="admin", role="owner")

    # Decodable with the current key alone — proves signing used SECRET, not PREVIOUS_SECRET.
    plain_current = JWTTokenService(secret_key=SECRET)
    plain_current.decode_token(pair.access_token, expected_type="access")


def test_previous_key_not_used_once_rotation_window_closes() -> None:
    old_service = JWTTokenService(secret_key=PREVIOUS_SECRET)
    pair = old_service.issue_pair(sub="s1", sub_type="admin", role="owner")

    no_fallback_service = JWTTokenService(secret_key=SECRET)  # rotation window closed
    with pytest.raises(InvalidTokenError):
        no_fallback_service.decode_token(pair.access_token, expected_type="access")


def test_empty_secret_key_rejected_at_construction() -> None:
    with pytest.raises(ValueError):
        JWTTokenService(secret_key="")
