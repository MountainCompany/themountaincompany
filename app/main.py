"""App factory — minimal for Stage 1: just the lifespan-wired schema bootstrap (§7.5) and a
health check. No /auth/* router, no AuthService, no get_current_admin dependency yet — those are
Stage 2 (docs/IMPLEMENTATION_PLAN.md §5), gated on Stage 1 review per that doc's own build order.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.v1.auth import router as auth_router
from app.core.config import get_settings
from app.db.bootstrap import run_startup_migrations


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    settings = get_settings()
    await asyncio.to_thread(run_startup_migrations, settings)
    yield


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(title="TrailOps API", lifespan=lifespan)

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_allowed_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.include_router(auth_router)

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    return app


app = create_app()
