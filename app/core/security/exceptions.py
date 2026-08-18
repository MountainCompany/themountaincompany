"""Errors raised by app/core/security/. Kept as plain exceptions (not HTTPException) so this
package stays framework-agnostic — translating these into HTTP responses is a router/dependency
concern (Stage 2), not something the security layer itself should know about. See jwt-service.md
§1.1: nothing in here should assume it's running inside FastAPI, since that's what keeps it
extractable into a standalone service later.
"""

from __future__ import annotations

from uuid import UUID


class TokenError(Exception):
    """Base for every error this package raises."""


class ExpiredTokenError(TokenError):
    """Signature valid, but `exp` has passed."""


class InvalidTokenError(TokenError):
    """Malformed, unsigned, or signed with a key we don't recognize (current or previous)."""


class WrongTokenTypeError(TokenError):
    """Decoded fine, but `typ` doesn't match what the caller expected (e.g. a refresh token
    presented where an access token was required, or vice versa)."""


class RefreshReuseDetectedError(TokenError):
    """A refresh token that was already rotated (or revoked) got presented again — per
    jwt-service.md §2.3 this means the token leaked or the client double-submitted. The caller
    (SessionService) has already revoked every other session for this subject by the time this
    is raised; the route layer's job is just to force re-login and, for admins, write an
    audit_log entry.
    """

    def __init__(self, subject_id: UUID) -> None:
        self.subject_id = subject_id
        super().__init__(f"refresh token reuse detected for subject {subject_id}; all sessions revoked")
