"""App settings — pydantic BaseSettings, read once at startup (jwt-service.md §9.2: never
re-fetched per request, never persisted anywhere the app writes to). Local dev reads from a
gitignored .env; prod reads from Railway's Variables store injected as real env vars — this
class doesn't know or care which, it just reads the process environment either way.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    ENVIRONMENT: Literal["development", "staging", "production"] = "development"

    # jwt-service.md §7.5 — dev applies migrations by hand, prod bootstraps its own schema on
    # first boot. Two different behaviours behind one flag, not two different code paths.
    AUTO_MIGRATE: bool = False

    DATABASE_URL: str = "postgresql+asyncpg://postgres:postgres@localhost:5432/trailops_dev"
    REDIS_URL: str = "redis://localhost:6379/0"

    # BACKEND_REQUIREMENTS.md §7 — "CORS restricted to the Vercel production domain, the
    # development preview domain, and localhost." Comma-separated; dev defaults to the two
    # ports Next.js commonly uses locally.
    CORS_ALLOWED_ORIGINS: str = "http://localhost:3000,http://127.0.0.1:3000"

    @property
    def cors_allowed_origins(self) -> list[str]:
        return [origin.strip() for origin in self.CORS_ALLOWED_ORIGINS.split(",") if origin.strip()]

    # jwt-service.md §0, §9.2 — HS256, single shared secret. No default: booting without one
    # set is a configuration error, not something to silently paper over with "changeme".
    JWT_SECRET_KEY: str = Field(...)
    JWT_SECRET_KEY_PREVIOUS: str | None = None
    OTP_HASH_PEPPER: str = Field(...)

    # Stage 2 (app/db/seed.py) — first `owner` admin account. Optional here since Stage 1 has
    # no seed step yet; required in practice once seed.py starts reading these.
    INITIAL_ADMIN_EMAIL: str | None = None
    INITIAL_ADMIN_PASSWORD: str | None = None

    @property
    def database_url_sync(self) -> str:
        """Alembic (and the startup migration runner, §7.5) use a sync driver — psycopg —
        while the app's own runtime engine uses asyncpg. Same database, same DATABASE_URL,
        different driver in the connection string."""
        return self.DATABASE_URL.replace("+asyncpg", "+psycopg")


@lru_cache
def get_settings() -> Settings:
    return Settings()
