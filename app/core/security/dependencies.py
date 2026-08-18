"""FastAPI-facing dependencies — the one place in app/core/security/ allowed to know about
FastAPI/HTTP at all. Everything below this line translates TokenError subclasses into
HTTPExceptions; everything above (ports.py, jwt_service.py, session_service.py) stays
framework-agnostic on purpose (jwt-service.md §1.1).
"""

from __future__ import annotations

from uuid import UUID

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings, get_settings
from app.db.base import get_db
from app.models.admin_user import AdminUser

from .exceptions import ExpiredTokenError, InvalidTokenError, WrongTokenTypeError
from .jwt_service import JWTTokenService

# tokenUrl is only used by FastAPI's auto-generated /docs "Authorize" button to know where to
# POST credentials — auto_error=False so a missing header raises our own 401, not Starlette's.
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login", auto_error=False)

_NOT_AUTHENTICATED = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Not authenticated",
    headers={"WWW-Authenticate": "Bearer"},
)


def get_token_service(settings: Settings = Depends(get_settings)) -> JWTTokenService:
    return JWTTokenService(
        secret_key=settings.JWT_SECRET_KEY,
        previous_secret_key=settings.JWT_SECRET_KEY_PREVIOUS,
    )


async def get_current_admin(
    token: str | None = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_db),
    token_service: JWTTokenService = Depends(get_token_service),
) -> AdminUser:
    if token is None:
        raise _NOT_AUTHENTICATED

    try:
        claims = token_service.decode_token(token, expected_type="access")
    except (ExpiredTokenError, InvalidTokenError, WrongTokenTypeError):
        raise _NOT_AUTHENTICATED from None

    # jwt-service.md §2.1 — the hard boundary: a participant token must never satisfy an admin
    # route, no matter what `sub` claims to be.
    if claims.sub_type != "admin":
        raise _NOT_AUTHENTICATED

    admin = await db.get(AdminUser, UUID(claims.sub))
    if admin is None or not admin.is_active:
        raise _NOT_AUTHENTICATED

    return admin


def require_role(*roles: str):
    """BACKEND_REQUIREMENTS.md §2:
        @router.post("/refunds", dependencies=[Depends(require_role("owner", "finance"))])
    """

    async def dependency(admin: AdminUser = Depends(get_current_admin)) -> AdminUser:
        if admin.role.value not in roles:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient role")
        return admin

    return dependency
