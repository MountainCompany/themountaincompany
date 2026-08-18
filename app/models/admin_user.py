"""jwt-service.md §6.1 — admin_users."""

from __future__ import annotations

import enum
import uuid
from datetime import datetime

from sqlalchemy import TIMESTAMP, Boolean, Enum, Text, text
from sqlalchemy.dialects.postgresql import CITEXT
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class AdminRole(enum.StrEnum):
    owner = "owner"
    event_manager = "event_manager"
    finance = "finance"


class AdminUser(Base):
    __tablename__ = "admin_users"

    id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()")
    )
    email: Mapped[str] = mapped_column(CITEXT(), unique=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(Text(), nullable=False)
    name: Mapped[str] = mapped_column(Text(), nullable=False)
    # create_type=False: the admin_role Postgres enum's lifecycle is owned by the Alembic
    # migration (migrations/versions/0001_admin_auth.py), never by ORM metadata — this app
    # never calls Base.metadata.create_all(), but setting this keeps that true even if a test
    # fixture ever does.
    role: Mapped[AdminRole] = mapped_column(
        Enum(AdminRole, name="admin_role", create_type=False), nullable=False
    )
    is_active: Mapped[bool] = mapped_column(Boolean(), nullable=False, server_default=text("true"))
    last_login_at: Mapped[datetime | None] = mapped_column(TIMESTAMP(timezone=True), nullable=True)
    organisation_id: Mapped[uuid.UUID | None] = mapped_column(PGUUID(as_uuid=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True), nullable=False, server_default=text("now()")
    )
    updated_at: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True), nullable=False, server_default=text("now()")
    )
