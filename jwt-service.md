# JWT Service — Design & Implementation Plan

**For:** `MountainCompany/themountaincompany` (FastAPI backend)
**Relates to:** `BACKEND_REQUIREMENTS.md` §2 (Roles and access), §3.1 (`admin_users`), §3.3 (`participants`)
**Status:** proposed design, pending confirmation — see §9 "Deviation from BACKEND_REQUIREMENTS.md"

---

## 0. Decisions locked in

| Question | Decision |
|---|---|
| Signing algorithm | **HS256** — single secret, single verifier (this FastAPI monolith). No other service needs to verify tokens independently, so an asymmetric keypair (RS256) buys nothing but ops overhead. |
| Participant session model | **Persistent login**, same mental model as admin: OTP verification issues an access+refresh pair, refreshable for weeks, not a single-use lookup token. |
| Token storage | **Separate tables** per subject — `admin_refresh_tokens` (→ `admin_users`) and `participant_sessions` (→ `participants`). Matches the per-entity table style already used throughout `BACKEND_REQUIREMENTS.md`; avoids a polymorphic/nullable dual-FK. |
| Extraction boundary | **Ports & adapters**, even under HS256 (§1.1). Every caller depends on a `Protocol`, never on `JWTTokenService` directly, so pulling this into its own microservice later is a one-file adapter swap, not a rewrite of every route. |
| Schema bootstrap | **Dev:** manual `alembic upgrade head` against the existing dev DB connection — no change to today's workflow. **Prod:** app runs the Alembic chain itself on first boot, advisory-lock guarded so N replicas booting together don't race (§7.5). |

---

## 1. Purpose

One JWT service module — `app/core/security/jwt_service.py` — is the single place that encodes, decodes, and validates tokens for **both** admin and participant auth. Two different login flows (admin email+password, participant phone+OTP) end up producing the same *kind* of artifact (a signed access/refresh pair), so they share:

- one `encode_token()` / `decode_token()` core
- one claim schema
- one refresh-rotation algorithm
- one revocation mechanism

...but they do **not** share database tables, claim values, or FastAPI dependencies. An admin token and a participant token must never be accepted by each other's routes, even though both come out of the same encoder.

---

## 1.1 Extraction boundary — ports & adapters

Staying HS256 (§0) doesn't mean staying coupled. The module is written so a future split into a standalone JWT microservice touches one adapter file, not every caller. The boundary is three `Protocol`s in `app/core/security/ports.py` — everything else in the codebase depends on the protocol, never on the concrete class:

| Port | Concrete adapter today | What moves on extraction |
|---|---|---|
| `TokenServicePort` — `issue_pair()`, `decode_token()`, `rotate()`, `revoke()`, `revoke_all()` | `JWTTokenService` (this doc, §5) | Becomes the entire surface of the new service. A `TokenServiceHTTPClient` implementing the same `Protocol` replaces the in-process adapter behind one DI binding. `AuthService`, `require_role`, `require_participant` don't change a line. |
| `RefreshTokenStorePort` — `save()`, `find_by_jti()`, `mark_revoked()`, `revoke_all_for_subject()` | Direct SQLAlchemy against `admin_refresh_tokens` / `participant_sessions` | Either stays behind the new service's own DB (it owns just these two tables — no joins outside auth) or, if the monolith's DB isn't split yet, the new service keeps read/write access to only those two tables. |
| `PasswordHasherPort` — `hash()`, `verify()`, `needs_rehash()` | `Argon2PasswordHasher` | Arguably never extracts — password verification is an admin-login concern, not a token concern. Kept as its own port so it isn't accidentally wired into `TokenServicePort`. |

**Rule that keeps this true in practice:** no file outside `app/core/security/` imports `jose`, `argon2`, or the `admin_refresh_tokens`/`participant_sessions` SQLAlchemy models directly. Routers and other services import the `Port` protocols and reach the adapter only through DI (`Depends(get_token_service)`). That indirection is what makes "swap HS256-in-process for an HTTP call to the new service" a one-file change instead of a grep-and-replace.

**What extraction looks like later, concretely:** stand up the new service, give it `JWT_SECRET_KEY` from the same secret manager (HS256 means the new service needs the *same* secret, not a separate keypair — that's the real cost of staying symmetric, see §0), point the new `TokenServiceHTTPClient` adapter at it, flip one DI binding in `app/core/security/dependencies.py`. Nothing in `AuthService`, the routers, or the `require_*` dependencies changes.

**Cost of doing this now:** one extra layer of indirection (protocols + DI wiring) a pure monolith wouldn't need. Accepted because retrofitting it after every caller is already coupled to the concrete class means rewriting every caller — the exact trade `docs/IMPLEMENTATION_PLAN.md` §2 already argues for.

---

## 2. Token design

### 2.1 Claims (common to both subjects)

```json
{
  "sub": "3fa1e2b0-...",       // admin_user.id or participant.id
  "sub_type": "admin",         // "admin" | "participant" — hard boundary between the two worlds
  "typ": "access",             // "access" | "refresh"
  "role": "event_manager",     // admin: owner|event_manager|finance. participant: fixed "self"
  "jti": "8c2e...",            // matches the DB row id for refresh tokens; random uuid4 for access tokens
  "iat": 1755417600,
  "exp": 1755418500,
  "iss": "trailops-api"
}
```

`sub_type` + `role` are checked on every protected route. A participant token can never satisfy `require_role(...)`, and an admin token can never satisfy `require_participant()`, regardless of what `sub` claims to be.

### 2.2 Lifetimes

| Token | Subject | TTL | Rotation |
|---|---|---|---|
| Access | admin | 15 min | stateless, not stored, not revocable — short TTL is the mitigation |
| Refresh | admin | 7 days, sliding | rotated on every use, stored hashed in `admin_refresh_tokens` |
| Access | participant | 15 min | same as above |
| Refresh | participant | 30 days, sliding | rotated on every use, stored hashed in `participant_sessions` |

Sliding = every successful refresh issues a new refresh token with a full new TTL window and revokes the one just used (see §2.3). A refresh token that's never used simply expires.

### 2.3 Rotation & reuse detection

On `POST /auth/refresh` (admin) or `POST /public/lookup/refresh` (participant):

1. Decode the refresh JWT, verify signature + `exp`.
2. Look up the row by `jti` in the appropriate table.
3. If `revoked_at IS NOT NULL` → **reuse detected**. This means either the token leaked or the client double-submitted. Revoke the entire chain (walk `replaced_by_id` links back, or simpler: revoke every non-revoked token for that `admin_user_id`/`participant_id`) and force re-login. Log to `audit_log` for admin; log a security event for participant.
4. Otherwise: mark the row `revoked_at = now()`, insert a new row, set `replaced_by_id` on the old row → new row's id, issue new access+refresh pair.

### 2.4 Revocation / logout

- **Access tokens are stateless** — no DB check per request, no blacklist. The 15-minute TTL is the entire mitigation for "I want this token dead right now." This is an explicit tradeoff for latency (matches the p95 targets in `BACKEND_REQUIREMENTS.md` §8) — acceptable because refresh tokens (the long-lived, dangerous artifact) are fully revocable.
- **Logout** = revoke the presented refresh token row (`revoked_at = now()`).
- **Logout all devices** (admin password change, or participant reports a lost/stolen phone) = revoke every non-revoked refresh row for that subject.

### 2.5 Secrets

- `JWT_SECRET_KEY` in the secret store (never in the repo — per `BACKEND_REQUIREMENTS.md` §7).
- Keep `JWT_SECRET_KEY_PREVIOUS` as an optional second verification key during a rotation window: verify against current, fall back to previous, sign only with current. Lets you rotate the secret without invalidating every live session instantly.
- OTP pepper: `OTP_HASH_PEPPER`, separate secret, used only for hashing OTP codes (§4.2).

---

## 3. Two flows through the same service

### 3.1 Admin login (`BACKEND_REQUIREMENTS.md` §2, §4 "Admin")

```
POST /api/v1/auth/login   { email, password }
  → look up admin_users by email
  → verify password_hash (argon2id), check is_active
  → jwt_service.issue_pair(sub=admin.id, sub_type="admin", role=admin.role)
  → insert admin_refresh_tokens row (hashed refresh token)
  → admin_users.last_login_at = now()
  → audit_log: action="login"
  ← { access_token, refresh_token, role }

POST /api/v1/auth/refresh { refresh_token }
  → rotate per §2.3, scoped to admin_refresh_tokens
  ← new { access_token, refresh_token }

POST /api/v1/auth/logout  { refresh_token }
  → revoke the row
  ← 204
```

`require_role("owner", "finance")` and friends decode the access token, assert `sub_type == "admin"`, assert `role in allowed`, load the `admin_users` row, assert `is_active`.

### 3.2 Participant — login after registration

This is the flow that changes relative to the current `BACKEND_REQUIREMENTS.md` wording ("participants never log in... returns a short-lived scoped token"). Under this design it becomes a real, persistent login, built on the same OTP verification step already specified:

```
Step 0 — registration (unauthenticated)
  POST /api/v1/public/registrations
  → creates/reuses a participants row (dedup by phone/email, §3.3 rules)
  → participant is NOT logged in yet — booking confirmation alone
    does not issue a token

Step 1 — request OTP (unauthenticated)
  POST /api/v1/public/lookup/request-otp   { phone }
  → rate limit: 3 sends / number / hour (Redis counter)
  → generate 4-digit OTP, hash it (HMAC-SHA256 + OTP_HASH_PEPPER)
  → insert otp_verifications row: phone, otp_hash, expires_at = now()+10min, attempts=0
  → send via WhatsApp, SMS fallback on delivery failure
  ← 202 (never reveal whether the phone exists)

Step 2 — verify OTP (unauthenticated)
  POST /api/v1/public/lookup/verify-otp   { phone, otp }
  → fetch latest non-expired otp_verifications row for phone
  → attempts >= 5 → 429, force a new OTP request
  → hash mismatch → attempts += 1, 401
  → match → verified_at = now()
  → find participants row by phone (must exist — created at registration)
  → jwt_service.issue_pair(sub=participant.id, sub_type="participant", role="self")
  → insert participant_sessions row (hashed refresh token)
  ← { access_token, refresh_token }
    (client stores these — httpOnly cookie on web, secure storage on mobile web)

Step 3 — authenticated participant requests, from here on
  GET  /api/v1/public/bookings              Authorization: Bearer <access_token>
  POST /api/v1/public/bookings/{id}/pay-balance
  POST /api/v1/public/bookings/{id}/cancel
  → require_participant() decodes the access token, asserts sub_type == "participant",
    takes participant_id ONLY from the token — never from a query param or body.
    This is what keeps the scoping promise: a participant can only ever see
    bookings tied to their own participant_id, because the id never comes
    from client-supplied input.

Step 4 — refresh (unauthenticated call, refresh token as bearer)
  POST /api/v1/public/lookup/refresh   { refresh_token }
  → rotate per §2.3, scoped to participant_sessions
  ← new { access_token, refresh_token }

Step 5 — logout
  POST /api/v1/public/lookup/logout   { refresh_token }
  → revoke the row
```

Why unify this in the JWT service rather than building a second, parallel auth mechanism: the crypto, rotation, and revocation logic is identical between the two subjects — the only real differences are *which table* a refresh token is checked against and *what claims* come out. Building two implementations of token rotation is exactly the kind of thing that drifts (one gets a security fix, the other doesn't). One service, two thin wrappers (`issue_admin_session()`, `issue_participant_session()`) that call the same core with different `sub_type`.

---

## 4. Hashing choices

### 4.1 Admin passwords

Argon2id (`argon2-cffi`, via `passlib[argon2]`), OWASP-recommended parameters. Never bcrypt-only — argon2id is the current baseline for new systems.

### 4.2 OTP codes

A 4-digit OTP has only 10,000 possible values — hash strength is not what protects it, the **attempt cap (5) + rate limit (3 sends/hour) + 10-minute expiry** are what protect it. Still: never store the OTP in plaintext or log it. Hash with `HMAC-SHA256(otp, OTP_HASH_PEPPER)` — cheap and sufficient given the actual threat model here (online guessing, not offline cracking of a stolen hash).

### 4.3 Refresh tokens

Store `SHA-256(raw_refresh_jwt)` in the DB, not the raw token. The token is already signed, but this is defense-in-depth: a leaked DB dump doesn't hand out working refresh tokens directly, since the hash isn't the credential.

---

## 5. FastAPI dependencies

```python
# app/core/security/jwt_service.py
def issue_pair(sub: str, sub_type: Literal["admin", "participant"], role: str) -> TokenPair: ...
def decode_token(token: str, expected_type: Literal["access", "refresh"]) -> TokenClaims: ...

# app/core/security/dependencies.py
async def get_current_admin(token: str = Depends(oauth2_scheme)) -> AdminUser:
    claims = decode_token(token, "access")
    if claims.sub_type != "admin":
        raise HTTPException(401)
    admin = await load_admin(claims.sub)
    if not admin.is_active:
        raise HTTPException(401)
    return admin

def require_role(*roles: str):
    async def dep(admin: AdminUser = Depends(get_current_admin)):
        if admin.role not in roles:
            raise HTTPException(403)
        return admin
    return dep

async def require_participant(token: str = Depends(oauth2_scheme)) -> Participant:
    claims = decode_token(token, "access")
    if claims.sub_type != "participant":
        raise HTTPException(401)
    return await load_participant(claims.sub)   # id comes from the token, never from the request
```

---

## 6. DB schema

### 6.1 `admin_users` (already specified in `BACKEND_REQUIREMENTS.md` §3.1 — restated with types)

| Column | Type | Notes |
|---|---|---|
| id | UUID pk | |
| email | citext, unique, indexed | |
| password_hash | text | argon2id |
| name | text | |
| role | enum(`owner`,`event_manager`,`finance`) | |
| is_active | boolean, default true | |
| last_login_at | timestamptz, nullable | |
| organisation_id | UUID, nullable | multi-tenancy placeholder, §7 |
| created_at / updated_at | timestamptz | |

### 6.2 `admin_refresh_tokens` (new)

| Column | Type | Notes |
|---|---|---|
| id | UUID pk | this is the `jti` embedded in the JWT |
| admin_user_id | UUID, FK → admin_users.id, indexed | |
| token_hash | text, unique, indexed | SHA-256 of the raw refresh JWT |
| issued_at | timestamptz | |
| expires_at | timestamptz, indexed | for the sweep job |
| revoked_at | timestamptz, nullable | |
| replaced_by_id | UUID, nullable, self-FK | rotation chain |
| user_agent | text, nullable | |
| ip_address | inet, nullable | |

### 6.3 `otp_verifications` (new)

| Column | Type | Notes |
|---|---|---|
| id | UUID pk | |
| phone | text, indexed | not unique — many rows per phone over time |
| purpose | enum(`login`), default `login` | room to extend (e.g. `balance_payment`) without a new table |
| otp_hash | text | HMAC-SHA256 + pepper |
| attempts | int, default 0 | |
| max_attempts | int, default 5 | |
| expires_at | timestamptz, indexed | |
| verified_at | timestamptz, nullable | |
| created_at | timestamptz, indexed | drives the "3 sends/hour" rate-limit query |

### 6.4 `participant_sessions` (new)

| Column | Type | Notes |
|---|---|---|
| id | UUID pk | `jti` |
| participant_id | UUID, FK → participants.id, indexed | |
| token_hash | text, unique, indexed | |
| issued_at | timestamptz | |
| expires_at | timestamptz, indexed | |
| revoked_at | timestamptz, nullable | |
| replaced_by_id | UUID, nullable, self-FK | |
| user_agent | text, nullable | |
| ip_address | inet, nullable | |

**Ordering constraint:** `participant_sessions` and `otp_verifications` both reference/target `participants`, which per `BACKEND_REQUIREMENTS.md` §9 build order is created in **slice 4 (Registrations)**, not slice 1 (Foundation). So this ships as **two migrations**, not one — see §7.

---

## 7. Alembic migrations

### 7.1 Revision A — ships with Foundation (build-order slice 1)

`admin_users` + `admin_refresh_tokens`. No dependency on `participants`.

```python
"""admin auth: admin_users, admin_refresh_tokens

Revision ID: 0001_admin_auth
Revises:
Create Date: 2026-08-17
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql as pg

revision = "0001_admin_auth"
down_revision = None
branch_labels = None
depends_on = None

admin_role = pg.ENUM("owner", "event_manager", "finance", name="admin_role")


def upgrade() -> None:
    op.execute("CREATE EXTENSION IF NOT EXISTS pgcrypto")
    admin_role.create(op.get_bind(), checkfirst=True)

    op.create_table(
        "admin_users",
        sa.Column("id", pg.UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("gen_random_uuid()")),
        sa.Column("email", pg.CITEXT(), nullable=False),
        sa.Column("password_hash", sa.Text(), nullable=False),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("role", admin_role, nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("last_login_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("organisation_id", pg.UUID(as_uuid=True), nullable=True),
        sa.Column("created_at", sa.TIMESTAMP(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
        sa.Column("updated_at", sa.TIMESTAMP(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
    )
    op.create_unique_constraint("uq_admin_users_email", "admin_users", ["email"])

    op.create_table(
        "admin_refresh_tokens",
        sa.Column("id", pg.UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("gen_random_uuid()")),
        sa.Column("admin_user_id", pg.UUID(as_uuid=True),
                  sa.ForeignKey("admin_users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("token_hash", sa.Text(), nullable=False),
        sa.Column("issued_at", sa.TIMESTAMP(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
        sa.Column("expires_at", sa.TIMESTAMP(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("replaced_by_id", pg.UUID(as_uuid=True),
                  sa.ForeignKey("admin_refresh_tokens.id", ondelete="SET NULL"), nullable=True),
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
```

### 7.2 Revision B — ships with Registrations (build-order slice 4, after `participants` exists)

`otp_verifications` + `participant_sessions`. Set `down_revision` to whatever migration created the `participants` table in your actual history — placeholder below.

```python
"""participant auth: otp_verifications, participant_sessions

Revision ID: 0004_participant_auth
Revises: <revision_that_created_participants>
Create Date: 2026-08-17
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql as pg

revision = "0004_participant_auth"
down_revision = "<revision_that_created_participants>"
branch_labels = None
depends_on = None

otp_purpose = pg.ENUM("login", name="otp_purpose")


def upgrade() -> None:
    otp_purpose.create(op.get_bind(), checkfirst=True)

    op.create_table(
        "otp_verifications",
        sa.Column("id", pg.UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("gen_random_uuid()")),
        sa.Column("phone", sa.Text(), nullable=False),
        sa.Column("purpose", otp_purpose, nullable=False, server_default="login"),
        sa.Column("otp_hash", sa.Text(), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("max_attempts", sa.Integer(), nullable=False, server_default="5"),
        sa.Column("expires_at", sa.TIMESTAMP(timezone=True), nullable=False),
        sa.Column("verified_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("created_at", sa.TIMESTAMP(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
    )
    op.create_index("ix_otp_verifications_phone", "otp_verifications", ["phone"])
    op.create_index(
        "ix_otp_verifications_phone_created_at", "otp_verifications", ["phone", "created_at"]
    )

    op.create_table(
        "participant_sessions",
        sa.Column("id", pg.UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("gen_random_uuid()")),
        sa.Column("participant_id", pg.UUID(as_uuid=True),
                  sa.ForeignKey("participants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("token_hash", sa.Text(), nullable=False),
        sa.Column("issued_at", sa.TIMESTAMP(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
        sa.Column("expires_at", sa.TIMESTAMP(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("replaced_by_id", pg.UUID(as_uuid=True),
                  sa.ForeignKey("participant_sessions.id", ondelete="SET NULL"), nullable=True),
        sa.Column("user_agent", sa.Text(), nullable=True),
        sa.Column("ip_address", pg.INET(), nullable=True),
    )
    op.create_unique_constraint(
        "uq_participant_sessions_token_hash", "participant_sessions", ["token_hash"]
    )
    op.create_index(
        "ix_participant_sessions_participant_id", "participant_sessions", ["participant_id"]
    )
    op.create_index(
        "ix_participant_sessions_expires_at", "participant_sessions", ["expires_at"]
    )


def downgrade() -> None:
    op.drop_table("participant_sessions")
    op.drop_table("otp_verifications")
    otp_purpose.drop(op.get_bind(), checkfirst=True)
```

---

## 7.5 DB schema bootstrap — dev vs prod

One migration chain (§7 — Revision A, then Revision B once Registrations ships), two different ways it gets applied, switched by `ENVIRONMENT`:

### Dev

No special JWT-only behaviour. Same dev database connection (`DATABASE_URL` in `.env`) the rest of the app already uses for everything else. Schema changes are applied the normal Alembic way, by hand, same as every other model in the project:

```
alembic upgrade head
```

Nothing auto-creates in dev — same discipline as the rest of the schema, so every migration still gets reviewed in a PR (`BACKEND_REQUIREMENTS.md` §10: every model change ships `upgrade` + `downgrade`).

### Prod — first boot creates the schema automatically, efficiently, and exactly once

Requirement: the first time this app starts against a fresh prod database, `admin_users` and `admin_refresh_tokens` (and later `otp_verifications` + `participant_sessions`) must exist before the first request is served — no operator running `alembic upgrade head` by hand against prod.

Design — a startup migration runner that drives Alembic itself, not raw `CREATE TABLE IF NOT EXISTS`:

```python
# app/db/bootstrap.py
JWT_SCHEMA_LOCK_KEY = 0x4A57545F  # arbitrary fixed int, stable across boots — the advisory-lock key

async def run_startup_migrations(settings: Settings) -> None:
    if not settings.AUTO_MIGRATE:              # default: true in prod, false in dev/staging
        return

    engine = create_engine(settings.DATABASE_URL)
    with engine.connect() as conn:
        # 1. Fast path — near-zero cost on every boot after the first.
        #    alembic_version is the one row Alembic maintains; if we're
        #    already at head, return without ever touching the lock.
        if _current_revision(conn) == _head_revision():
            return

        # 2. Slow path — taken once, on the very first boot against a
        #    fresh DB (or right after a real migration ships). A Postgres
        #    advisory lock means that if prod boots N replicas/workers
        #    concurrently, only one of them runs `upgrade head`; the
        #    rest block briefly on the lock, then hit the fast path
        #    above and return the instant the first one commits.
        conn.execute(text("SELECT pg_advisory_lock(:key)"), {"key": JWT_SCHEMA_LOCK_KEY})
        try:
            if _current_revision(conn) != _head_revision():
                t0 = time.monotonic()
                alembic_command.upgrade(alembic_cfg, "head")
                logger.info("schema bootstrap: migrated to head",
                            extra={"revision": _head_revision(), "elapsed_s": time.monotonic() - t0})
        finally:
            conn.execute(text("SELECT pg_advisory_unlock(:key)"), {"key": JWT_SCHEMA_LOCK_KEY})

# app/main.py
@asynccontextmanager
async def lifespan(app: FastAPI):
    await run_startup_migrations(settings)
    yield
```

Why this shape, not something simpler:

| Alternative considered | Why not |
|---|---|
| Raw `CREATE TABLE IF NOT EXISTS` at startup, bypassing Alembic | Two schema-creation paths (Alembic for dev/CI, raw SQL for prod) drift the moment someone adds a column and forgets the second path. Alembic's `upgrade head` stays the single source of truth for schema, in every environment. |
| `alembic upgrade head` on every boot, no lock, no fast-path check | Fine for one instance. Breaks the moment prod runs more than one replica/worker at boot (Railway/Render/K8s all do rolling or parallel starts) — two processes racing `CREATE TABLE`/`ALTER TABLE` concurrently is exactly what deadlocks or half-applies a migration. |
| Migration as a separate CI/CD deploy step, app never migrates itself | The more conventional pattern once there's a real deploy pipeline — worth moving to later. Not assumed here because the ask was specifically "when this runs in prod for the first time, it creates the schema at start" — the app itself, on boot, no separate operator step. `AUTO_MIGRATE=false` is the one-line switch to that pattern later; no rewrite needed. |
| Lazy per-request table check (create-on-first-`INSERT`) | Wrong layer — schema readiness is a startup-time concern. Checking per-request adds a query to the hot path forever for something that only ever matters once. |

Config additions (`core/config.py`, `.env.example`):

| Var | Dev | Prod |
|---|---|---|
| `ENVIRONMENT` | `development` | `production` |
| `AUTO_MIGRATE` | `false` | `true` |
| `DATABASE_URL` | dev DB connection, already in use today | prod DB connection, from the secret manager (§9.2) |

`AUTO_MIGRATE` is the one knob — same code path in both environments, the flag decides whether it's a no-op. Nothing about the runner is JWT-specific: it runs the *whole* Alembic chain, not a JWT-only subset. Since Revision A (and later B) are the first migrations to exist in this project, "runs the whole chain" and "creates the JWT schema" are the same statement at this point in the build order — that stops being true once other domains (events, bookings, …) add their own migrations, and the runner doesn't need to change when it does.

---

## 8. Implementation plan

| Phase | Ships with (build order §9) | Work |
|---|---|---|
| 0 — Infra | Foundation | `JWT_SECRET_KEY`, `JWT_SECRET_KEY_PREVIOUS`, `OTP_HASH_PEPPER`, `ENVIRONMENT`, `AUTO_MIGRATE` in `.env.example`; add `argon2-cffi`, `python-jose` to deps; `core/config.py` settings |
| 0.5 — Ports & schema bootstrap | Foundation | `app/core/security/ports.py` (`TokenServicePort`, `RefreshTokenStorePort`, `PasswordHasherPort`, §1.1); `app/db/bootstrap.py` startup migration runner + advisory lock (§7.5); wire into FastAPI `lifespan`; verify against a fresh local Postgres with `AUTO_MIGRATE=true` before relying on it for prod |
| 1 — Admin auth core | Foundation | `jwt_service.py` (`JWTTokenService`, the `TokenServicePort` adapter — encode/decode core, generic to both subjects); `admin_users` model + Revision A; password hashing util; `/auth/login`, `/auth/refresh`, `/auth/logout`; `admin_refresh_tokens` + rotation; `get_current_admin`, `require_role`; audit_log write on login |
| 2 — OTP infra | Registrations | `otp_verifications` model + part of Revision B; Redis rate limiter (3/hour); `/public/lookup/request-otp`; WhatsApp send + SMS fallback wiring |
| 3 — Participant sessions | Registrations | `participant_sessions` model (rest of Revision B); `/public/lookup/verify-otp` issuing the pair via the same `jwt_service`; `/public/lookup/refresh`, `/public/lookup/logout`; `require_participant`; wire into `GET /public/bookings`, `pay-balance`, `cancel` |
| 4 — Hardening | ongoing | refresh-reuse detection (§2.3); "logout all devices" on admin password change; sweep job (Celery beat) to hard-delete/archive expired+revoked rows past a retention window; structured audit logging for participant auth events |
| 5 — Tests | every PR in phases 1–4 | see §8.1 — target 100% coverage on this module, same bar as payment/seat-locking per `BACKEND_REQUIREMENTS.md` §8 |

### 8.1 Test checklist

- `jwt_service`: encode/decode round-trip, expired token rejected, tampered signature rejected, wrong `typ` rejected (access used where refresh expected and vice versa), `sub_type` mismatch rejected.
- Admin: login success/failure (wrong password, inactive account), refresh rotation, refresh reuse triggers full revocation, logout revokes exactly one row, `require_role` blocks the wrong role.
- Participant: OTP request rate-limited at 4th send/hour, OTP expiry at 10 min, lockout at 5 failed attempts, verify success issues a working pair, a participant's access token cannot see another participant's bookings (this is the one to fuzz hardest — id must never be reachable from client input).
- Concurrency: two simultaneous refresh calls with the same token — exactly one should succeed, the other should trigger reuse detection.

---

## 9. Bootstrap & secret handling — confirmed answers

### 9.1 First admin user — seeded, not migrated

The Alembic migration (Revision A, §7.1) only creates an **empty** `admin_users` table. A default `owner` account is never written as migration data — a hardcoded email/password in a migration file sits in git history in plaintext forever, readable by anyone with repo access, and can't be rotated without a new migration.

Instead: `app/db/seed.py` runs on deploy (or via a one-off `python -m app.db.seed` command), and:

1. Checks whether any `admin_users` row with `role = 'owner'` exists.
2. If not, reads `INITIAL_ADMIN_EMAIL` / `INITIAL_ADMIN_PASSWORD` from the environment, hashes the password (argon2id), and inserts the row.
3. If an owner already exists, does nothing — safe to run on every deploy.
4. Logs a warning to rotate the password on first login.

`INITIAL_ADMIN_EMAIL` / `INITIAL_ADMIN_PASSWORD` are documented (shape only, no real value) in `.env.example`, same as every other secret.

### 9.2 Where the secret lives — never in the DB, never in the repo

HS256 means there is exactly one secret, `JWT_SECRET_KEY` — no public key exists; that split only applies under RS256, which was considered and declined (§0).

- **Production:** stored in Railway's "Variables" store (§9.4 — decided) and injected as an env var at deploy/boot time. The app reads it once, at startup, through `core/config.py` (`pydantic BaseSettings`) — never re-fetched per request, never persisted anywhere the app writes to, and specifically never in Postgres.
- **Local dev:** a gitignored `.env` file.
- **Repo:** `.env.example` documents the variable's *shape* only (`JWT_SECRET_KEY=changeme`), matching the existing "no secrets in the repo" rule in `BACKEND_REQUIREMENTS.md` §7.
- Same treatment for `JWT_SECRET_KEY_PREVIOUS` (rotation window, §2.5) and `OTP_HASH_PEPPER`.

### 9.3 Refresh tokens — hashed at rest (confirmed)

As specified in §4.3: `admin_refresh_tokens.token_hash` and `participant_sessions.token_hash` store `SHA-256(raw_refresh_jwt)`, never the raw token. A row in either table is useless on its own for authentication — it's a revocation record, not a credential.

### 9.4 Infra accounts — where things run (decided)

Neither Supabase, Vercel, nor GoDaddy — the three pieces already in place — actually run this FastAPI backend or its Celery worker (`BACKEND_REQUIREMENTS.md` §1 requires Celery+Redis for SLA-expiry, notification dispatch, and the refresh-token sweep job in §8 Phase 4). That gap is closed as follows:

| Provider | Role | Notes |
|---|---|---|
| **Supabase** | PostgreSQL 16 (§1 stack) | Dev: existing dev project, connection via `.env`. Prod: a **separate** Supabase project, created when Stage 1/2 is ready to deploy — kept isolated from dev, matches the fresh-DB assumption in §7.5's bootstrap runner. Use the **direct** connection string (not the pgbouncer pooler) for the bootstrap runner's advisory-lock calls. Supabase bundles its own Auth (GoTrue) — **not used**; only its Postgres is consumed, so there's no second, competing auth system alongside `jwt_service`. |
| **Upstash** | Redis (§1 stack: rate limits, Celery broker, event-page cache) | Free tier (256 MB, 500K commands/month) is sufficient at current scale — 2–3 admins, ~100 participant registrations/week puts real usage well under those limits. |
| **Railway** | FastAPI API service + Celery worker service, both from this repo; also the env-var store for `JWT_SECRET_KEY` / `JWT_SECRET_KEY_PREVIOUS` / `OTP_HASH_PEPPER` / `DATABASE_URL` / `REDIS_URL` / `ENVIRONMENT` / `AUTO_MIGRATE` | Chosen over Render: Render's always-on tier is a flat $7/service/month ($14/mo for API+worker), its free tier sleeps after 15 min idle (breaks worker reliability — a sleeping worker won't fire the 24h SLA-expiry job on time). Railway's usage-based billing fits a mostly-idle, low-traffic app better. One Railway project, two services, sharing env vars — keeps `JWT_SECRET_KEY` in exactly one place rather than duplicated across two hosting providers. |
| **Vercel** | Frontend only (`mountaincompany-UI`, `BACKEND_REQUIREMENTS.md` §0) | No role in this backend — Vercel serverless functions can't run a persistent Celery worker, which rules it out for the API too (keeping API and worker on the same host, per the Railway row above, avoids splitting `JWT_SECRET_KEY` across two env stores). |
| **GoDaddy** | DNS only | Points `api.<domain>` at Railway's generated domain once deployed. No app credentials involved. |

---

## 10. Deviation from `BACKEND_REQUIREMENTS.md` — flag for sign-off

`BACKEND_REQUIREMENTS.md` §2 currently states *"admin-only authentication. Participants never log in"* and describes the OTP flow as returning a single "short-lived scoped token." This design turns that into a real, persistent participant login (refresh-token backed, 30-day sliding session), per your direction that participants log in after registration.

This is a genuine change to a stated requirement, not just an implementation detail — worth a one-line confirmation back into `BACKEND_REQUIREMENTS.md` §2 and §11 (open questions) so the SRS and the build brief stay in sync, same as the other **DECISION** markers already in that doc.
