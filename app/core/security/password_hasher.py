"""Argon2PasswordHasher — the PasswordHasherPort adapter. Argon2id via argon2-cffi
(jwt-service.md §4.1: OWASP-recommended, memory-hard; never bcrypt-only for new systems).
"""

from __future__ import annotations

from argon2 import PasswordHasher as _Argon2PasswordHasher
from argon2.exceptions import InvalidHash, VerifyMismatchError


class Argon2PasswordHasher:
    def __init__(self) -> None:
        self._hasher = _Argon2PasswordHasher()  # argon2-cffi's library defaults are argon2id

    def hash(self, plain: str) -> str:
        return self._hasher.hash(plain)

    def verify(self, plain: str, hashed: str) -> bool:
        try:
            self._hasher.verify(hashed, plain)
        except (VerifyMismatchError, InvalidHash):
            return False
        return True

    def needs_rehash(self, hashed: str) -> bool:
        """True if `hashed` was produced with weaker-than-current parameters — e.g. after an
        OWASP recommendation change. Caller's job (AuthService, Stage 2) to re-hash and save on
        the next successful login when this is true; never rehash on a failed verify."""
        return self._hasher.check_needs_rehash(hashed)
