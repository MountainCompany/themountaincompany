"""The extraction boundary. See jwt-service.md §1.1.

Every caller elsewhere in the codebase (routers, AuthService, require_role/require_participant)
depends on the Protocols in this file — never on the concrete adapters (JWTTokenService,
Argon2PasswordHasher, AdminRefreshTokenStore). That's the whole trick: swapping HS256-in-process
for an HTTP call to a standalone JWT microservice later means writing one new adapter class and
flipping one DI binding, not touching every caller.

Rule that keeps this true in practice: no file outside app/core/security/ should import `jose`,
`argon2`, or a token-table SQLAlchemy model directly.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Literal, Protocol
from uuid import UUID

SubType = Literal["admin", "participant"]
TokenType = Literal["access", "refresh"]


# --- TokenServicePort ------------------------------------------------------------------------
#
# Deliberately pure crypto: no DB access, no I/O beyond reading the clock. That statelessness is
# what makes it the cleanest possible extraction candidate — a future microservice's entire job
# is re-implementing this one class behind an HTTP handler. Rotation/revocation (which do need
# storage) live one layer up, in SessionService, which composes this port with
# RefreshTokenStorePort rather than baking DB access into the token engine itself.


@dataclass(frozen=True, slots=True)
class TokenPair:
    access_token: str
    refresh_token: str
    access_expires_at: datetime
    refresh_expires_at: datetime
    refresh_jti: str
    """Also the primary key the caller must use when persisting the refresh-token DB row —
    jwt-service.md §2.1: "jti ... matches the DB row id for refresh tokens." Generated here,
    before any DB write, so TokenServicePort never needs to know a row exists."""


@dataclass(frozen=True, slots=True)
class TokenClaims:
    sub: str
    sub_type: SubType
    typ: TokenType
    role: str
    jti: str
    iat: datetime
    exp: datetime
    iss: str


class TokenServicePort(Protocol):
    def issue_pair(self, *, sub: str, sub_type: SubType, role: str) -> TokenPair:
        """Encode a fresh access+refresh pair. Does not touch the database."""
        ...

    def decode_token(self, token: str, *, expected_type: TokenType) -> TokenClaims:
        """Verify signature + `exp`, assert `typ == expected_type`. Raises ExpiredTokenError,
        InvalidTokenError, or WrongTokenTypeError (app/core/security/exceptions.py) — never
        returns claims for a token that failed any of those checks."""
        ...


# --- RefreshTokenStorePort --------------------------------------------------------------------
#
# One Protocol, two adapters in the current design (jwt-service.md §6): AdminRefreshTokenStore
# over admin_refresh_tokens (built now, Stage 1) and a future ParticipantSessionStore over
# participant_sessions (Stage 6) — separate tables per subject, same shape, same Protocol.


@dataclass(frozen=True, slots=True)
class RefreshTokenRecord:
    id: UUID
    subject_id: UUID
    token_hash: str
    issued_at: datetime
    expires_at: datetime
    revoked_at: datetime | None
    replaced_by_id: UUID | None


class RefreshTokenStorePort(Protocol):
    async def save(self, record: RefreshTokenRecord) -> None: ...

    async def find_by_id(self, id: UUID) -> RefreshTokenRecord | None:
        """Plain lookup — used for the not-found/hash-mismatch check before a rotation attempt,
        and by revoke(), where a benign double-write racing another revoke is harmless
        (idempotent: revoked_at just gets set to `now()` twice)."""
        ...

    async def claim_for_rotation(self, id: UUID, *, replaced_by_id: UUID) -> bool:
        """The rotation lock, implemented as a single atomic conditional update — not a
        SELECT-then-UPDATE pair — specifically so two concurrent rotate() calls on the *same*
        refresh token can't both win: `UPDATE ... SET revoked_at = now(), replaced_by_id = :id
        WHERE id = :id AND revoked_at IS NULL`. Postgres's row-level locking on UPDATE serializes
        concurrent callers here even without an explicit `SELECT ... FOR UPDATE` — the second
        writer blocks until the first commits, then re-evaluates `revoked_at IS NULL` against the
        now-updated row and matches zero rows.

        Returns True if this call's UPDATE matched a row (it won the race — proceed to persist
        the new token), False if it matched none (already revoked, or never existed — the
        reuse-detection path, jwt-service.md §2.3 and the concurrency test in §8.1).
        """
        ...

    async def mark_revoked(self, id: UUID, *, replaced_by_id: UUID | None = None) -> None:
        """Unconditional revoke — used by revoke() (logout) only. rotate() uses
        claim_for_rotation() instead precisely because that path needs the conditional,
        race-safe version."""
        ...

    async def revoke_all_for_subject(self, subject_id: UUID) -> None:
        """"Logout all devices" (password change, reuse detected) — jwt-service.md §2.4."""
        ...


# --- PasswordHasherPort -------------------------------------------------------------------------
#
# Kept separate from TokenServicePort even though both concern "auth crypto" — password
# verification is an admin-login concern, not a token concern, and this port most likely never
# extracts even if the token engine does (jwt-service.md §1.1).


class PasswordHasherPort(Protocol):
    def hash(self, plain: str) -> str: ...
    def verify(self, plain: str, hashed: str) -> bool: ...
    def needs_rehash(self, hashed: str) -> bool: ...
