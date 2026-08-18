"""JWTTokenService — the TokenServicePort adapter. HS256 via python-jose (jwt-service.md §0:
locked decision, chosen over RS256 — microservice-readiness is handled through the ports
boundary in ports.py, not through the signing algorithm).

Pure crypto, same as the Protocol it implements: no DB access, no I/O beyond the clock. See
ports.py's module docstring for why that matters.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from jose import ExpiredSignatureError, JWTError, jwt

from .exceptions import ExpiredTokenError, InvalidTokenError, WrongTokenTypeError
from .ports import SubType, TokenClaims, TokenPair, TokenType

ISSUER = "trailops-api"
ALGORITHM = "HS256"

# jwt-service.md §2.2
ACCESS_TTL = timedelta(minutes=15)
ADMIN_REFRESH_TTL = timedelta(days=7)
PARTICIPANT_REFRESH_TTL = timedelta(days=30)


class JWTTokenService:
    def __init__(self, *, secret_key: str, previous_secret_key: str | None = None) -> None:
        """`previous_secret_key` supports the rotation window in jwt-service.md §2.5: verification
        falls back to it when the current key fails, signing always uses `secret_key` only."""
        if not secret_key:
            raise ValueError("secret_key must not be empty")
        self._secret_key = secret_key
        self._previous_secret_key = previous_secret_key or None

    def issue_pair(self, *, sub: str, sub_type: SubType, role: str) -> TokenPair:
        now = datetime.now(UTC)
        refresh_ttl = ADMIN_REFRESH_TTL if sub_type == "admin" else PARTICIPANT_REFRESH_TTL
        access_exp = now + ACCESS_TTL
        refresh_exp = now + refresh_ttl
        refresh_jti = str(uuid.uuid4())

        access_token = self._encode(
            sub=sub, sub_type=sub_type, typ="access", role=role,
            jti=str(uuid.uuid4()), iat=now, exp=access_exp,
        )
        refresh_token = self._encode(
            sub=sub, sub_type=sub_type, typ="refresh", role=role,
            jti=refresh_jti, iat=now, exp=refresh_exp,
        )

        return TokenPair(
            access_token=access_token,
            refresh_token=refresh_token,
            access_expires_at=access_exp,
            refresh_expires_at=refresh_exp,
            refresh_jti=refresh_jti,
        )

    def decode_token(self, token: str, *, expected_type: TokenType) -> TokenClaims:
        payload = self._decode(token)

        if payload.get("typ") != expected_type:
            raise WrongTokenTypeError(f"expected typ={expected_type!r}, got {payload.get('typ')!r}")

        return TokenClaims(
            sub=payload["sub"],
            sub_type=payload["sub_type"],
            typ=payload["typ"],
            role=payload["role"],
            jti=payload["jti"],
            iat=datetime.fromtimestamp(payload["iat"], tz=UTC),
            exp=datetime.fromtimestamp(payload["exp"], tz=UTC),
            iss=payload["iss"],
        )

    # -- internals ------------------------------------------------------------------------------

    def _encode(self, **claims: object) -> str:
        iat: datetime = claims.pop("iat")  # type: ignore[assignment]
        exp: datetime = claims.pop("exp")  # type: ignore[assignment]
        payload = {**claims, "iat": int(iat.timestamp()), "exp": int(exp.timestamp()), "iss": ISSUER}
        return jwt.encode(payload, self._secret_key, algorithm=ALGORITHM)

    def _decode(self, token: str) -> dict:
        try:
            return jwt.decode(token, self._secret_key, algorithms=[ALGORITHM], issuer=ISSUER)
        except ExpiredSignatureError as exc:
            raise ExpiredTokenError("token expired") from exc
        except JWTError:
            pass  # fall through to the previous-key retry below

        if self._previous_secret_key:
            try:
                return jwt.decode(token, self._previous_secret_key, algorithms=[ALGORITHM], issuer=ISSUER)
            except ExpiredSignatureError as exc:
                raise ExpiredTokenError("token expired") from exc
            except JWTError as exc:
                raise InvalidTokenError("signature verification failed") from exc

        raise InvalidTokenError("signature verification failed")
