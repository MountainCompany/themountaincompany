"""admin auth: admin_users, admin_refresh_tokens

Revision ID: 0001_admin_auth
Revises:
Create Date: 2026-08-17

See jwt-service.md §7.1 / §6.1-6.2 for the design this implements.
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql as pg

revision: str = "0001_admin_auth"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# create_type=False: the type's lifecycle is managed explicitly below (admin_role.create/.drop),
# not implicitly by create_table/drop_table — without this, create_table's own dispatch hook
# tries to CREATE TYPE a second time and collides with the explicit create() just above it.
admin_role = pg.ENUM("owner", "event_manager", "finance", name="admin_role", create_type=False)


def upgrade() -> None:
    op.execute("CREATE EXTENSION IF NOT EXISTS pgcrypto")
    op.execute("CREATE EXTENSION IF NOT EXISTS citext")
    admin_role.create(op.get_bind(), checkfirst=True)

    op.create_table(
        "admin_users",
        sa.Column(
            "id", pg.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")
        ),
        sa.Column("email", pg.CITEXT(), nullable=False),
        sa.Column("password_hash", sa.Text(), nullable=False),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("role", admin_role, nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("last_login_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("organisation_id", pg.UUID(as_uuid=True), nullable=True),
        sa.Column(
            "created_at", sa.TIMESTAMP(timezone=True), nullable=False, server_default=sa.text("now()")
        ),
        sa.Column(
            "updated_at", sa.TIMESTAMP(timezone=True), nullable=False, server_default=sa.text("now()")
        ),
    )
    op.create_unique_constraint("uq_admin_users_email", "admin_users", ["email"])

    op.create_table(
        "admin_refresh_tokens",
        sa.Column(
            "id", pg.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")
        ),
        sa.Column(
            "admin_user_id",
            pg.UUID(as_uuid=True),
            sa.ForeignKey("admin_users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("token_hash", sa.Text(), nullable=False),
        sa.Column(
            "issued_at", sa.TIMESTAMP(timezone=True), nullable=False, server_default=sa.text("now()")
        ),
        sa.Column("expires_at", sa.TIMESTAMP(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column(
            "replaced_by_id",
            pg.UUID(as_uuid=True),
            sa.ForeignKey("admin_refresh_tokens.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("user_agent", sa.Text(), nullable=True),
        sa.Column("ip_address", pg.INET(), nullable=True),
    )
    op.create_unique_constraint(
        "uq_admin_refresh_tokens_token_hash", "admin_refresh_tokens", ["token_hash"]
    )
    op.create_index(
        "ix_admin_refresh_tokens_admin_user_id", "admin_refresh_tokens", ["admin_user_id"]
    )
    op.create_index(
        "ix_admin_refresh_tokens_expires_at", "admin_refresh_tokens", ["expires_at"]
    )


def downgrade() -> None:
    op.drop_table("admin_refresh_tokens")
    op.drop_table("admin_users")
    admin_role.drop(op.get_bind(), checkfirst=True)
