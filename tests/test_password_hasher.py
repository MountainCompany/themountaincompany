from __future__ import annotations

from app.core.security.password_hasher import Argon2PasswordHasher


def test_hash_then_verify_succeeds() -> None:
    hasher = Argon2PasswordHasher()
    hashed = hasher.hash("correct horse battery staple")
    assert hasher.verify("correct horse battery staple", hashed) is True


def test_verify_wrong_password_fails() -> None:
    hasher = Argon2PasswordHasher()
    hashed = hasher.hash("correct horse battery staple")
    assert hasher.verify("wrong password", hashed) is False


def test_verify_garbage_hash_fails_not_raises() -> None:
    hasher = Argon2PasswordHasher()
    assert hasher.verify("anything", "not-a-real-argon2-hash") is False


def test_hash_is_never_the_plaintext() -> None:
    hasher = Argon2PasswordHasher()
    hashed = hasher.hash("correct horse battery staple")
    assert "correct horse battery staple" not in hashed


def test_freshly_hashed_password_does_not_need_rehash() -> None:
    hasher = Argon2PasswordHasher()
    hashed = hasher.hash("correct horse battery staple")
    assert hasher.needs_rehash(hashed) is False
