"""POST /auth/login|refresh|logout, GET /auth/me — docs/IMPLEMENTATION_PLAN.md §5.

Known gap, deliberately not closed in this pass: rate limiting on /auth/login
(docs/IMPLEMENTATION_PLAN.md §5's own deliverable list — "brute-force protection lives at this
layer, not in the token engine") needs Redis, which isn't wired up yet. Track before this goes
anywhere near a real prod login form.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security.admin_refresh_token_store import AdminRefreshTokenStore
from app.core.security.dependencies import get_current_admin, get_token_service
from app.core.security.exceptions import InvalidTokenError, RefreshReuseDetectedError
from app.core.security.jwt_service import JWTTokenService
from app.core.security.password_hasher import Argon2PasswordHasher
from app.core.security.session_service import SessionService
from app.db.base import get_db
from app.models.admin_user import AdminUser
from app.schemas.auth import AdminMeResponse, LoginRequest, LogoutRequest, RefreshRequest, TokenPairResponse
from app.services.auth_service import AuthService, InvalidCredentialsError

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])


async def get_auth_service(
    db: AsyncSession = Depends(get_db),
    token_service: JWTTokenService = Depends(get_token_service),
) -> AuthService:
    store = AdminRefreshTokenStore(db)
    session_service = SessionService(token_service, store)
    return AuthService(db, Argon2PasswordHasher(), session_service)


def _client_ip(request: Request) -> str | None:
    return request.client.host if request.client else None


@router.post("/login", response_model=TokenPairResponse)
async def login(
    body: LoginRequest,
    request: Request,
    auth_service: AuthService = Depends(get_auth_service),
) -> TokenPairResponse:
    try:
        pair, admin = await auth_service.login(
            email=body.email,
            password=body.password,
            user_agent=request.headers.get("user-agent"),
            ip_address=_client_ip(request),
        )
    except InvalidCredentialsError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password"
        ) from None

    return TokenPairResponse(
        access_token=pair.access_token, refresh_token=pair.refresh_token, role=admin.role.value
    )


@router.post("/refresh", response_model=TokenPairResponse)
async def refresh(
    body: RefreshRequest,
    auth_service: AuthService = Depends(get_auth_service),
    token_service: JWTTokenService = Depends(get_token_service),
) -> TokenPairResponse:
    try:
        pair = await auth_service.refresh(body.refresh_token)
    except RefreshReuseDetectedError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session revoked — please log in again",
        ) from None
    except InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token"
        ) from None

    # Cheap local decode (pure crypto, no DB) just to read `role` back out for the response body.
    claims = token_service.decode_token(pair.access_token, expected_type="access")
    return TokenPairResponse(
        access_token=pair.access_token, refresh_token=pair.refresh_token, role=claims.role
    )


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(body: LogoutRequest, auth_service: AuthService = Depends(get_auth_service)) -> None:
    try:
        await auth_service.logout(body.refresh_token)
    except InvalidTokenError:
        pass  # logout is idempotent — an already-invalid token is still "logged out"


@router.get("/me", response_model=AdminMeResponse)
async def me(admin: AdminUser = Depends(get_current_admin)) -> AdminMeResponse:
    """Not in the original Stage 2 deliverable list, added so there's an authenticated route to
    actually exercise get_current_admin against — the smallest possible proof that a Bearer
    access token from /login works end to end."""
    return AdminMeResponse(id=str(admin.id), email=admin.email, name=admin.name, role=admin.role.value)
