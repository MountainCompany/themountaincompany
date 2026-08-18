# TrailOps — Backend Requirements

**For:** `MountainCompany/themountaincompany` (FastAPI)
**Consumed by:** Claude Code, as the build brief for the backend
**Source of truth:** TrailOps SRS v2.1 + the approved UI prototype
**Version:** 1.0 · August 2026

---

## 0. How to read this document

This is a build brief, not a discussion document. Requirement IDs in brackets — `[A-4]`, `[P-11]` — refer to the SRS v2.1 admin and participant requirement tables. Where the SRS left something underspecified, this document makes the decision and says so explicitly; those are marked **DECISION**.

The UI prototype is the visual and behavioural contract. Where this document and the prototype disagree, raise it rather than guessing — the prototype has been reviewed by the client and several flows in it were refined past what the SRS describes.

**Two repos, no monorepo:**
- `MountainCompany/themountaincompany` — this backend
- `MountainCompany/mountaincompany-UI` — Next.js frontend, deployed on Vercel

**Branching:** `development` for all work; PR into `main`. `main` is production. Never commit directly to `main`.

---

## 1. Stack

| Concern | Choice | Notes |
|---|---|---|
| Framework | FastAPI | async endpoints throughout |
| Language | Python 3.12 | |
| Database | PostgreSQL 16 | required — row-level locking is not optional (§5.1) |
| ORM | SQLAlchemy 2.0 | async engine, typed `Mapped[]` style |
| Migrations | Alembic | every model change ships with a migration |
| Validation | Pydantic v2 | separate `Create` / `Update` / `Read` schemas |
| Background jobs | Celery + Redis | SLA expiry, notification dispatch, report generation |
| Cache / locks | Redis | |
| Auth | JWT, `python-jose` | access + refresh, role claims |
| Payments | Razorpay | UPI and QR only `[A-22]` |
| Messaging | WhatsApp Business API | SMS fallback via provider of choice |
| Storage | S3-compatible | event photos, galleries, uploaded ID documents |
| Testing | pytest + pytest-asyncio | |
| Lint / format | ruff | |

**Layout**

```
app/
  main.py               # app factory, middleware, router registration
  core/                 # config, security, dependencies, exceptions
  db/                   # session, base, seed
  models/               # SQLAlchemy models
  schemas/              # Pydantic schemas
  api/v1/               # routers, one module per resource
  services/             # business logic — routers stay thin
  workers/              # Celery tasks
  integrations/         # razorpay, whatsapp, sms, storage
migrations/
tests/
```

All routes under `/api/v1`. Business logic lives in `services/`, never in routers.

---

## 2. Roles and access

`[A-15]`, SRS §03 — **admin-only authentication. Participants never log in.**

| Role | Can |
|---|---|
| `owner` | everything, including role management and audit log |
| `event_manager` | events, itineraries, routes, participants, waitlist, reviews. **No** refunds, no payout data |
| `finance` | payments, refunds, manual collection, revenue analytics. Read-only on events |

Enforce with a dependency, not scattered `if` checks:

```python
@router.post("/refunds", dependencies=[Depends(require_role("owner", "finance"))])
```

Participants access their booking through **phone + OTP** (SRS §03 design note). OTP: 4 digits, 10-minute expiry, max 5 attempts, rate-limited to 3 sends per number per hour. Verification returns a short-lived scoped token that grants access to that phone number's bookings only — nothing else.

---

## 3. Data model

Every table: `id` (UUID), `created_at`, `updated_at`. Soft-delete via `archived_at` where the SRS implies archiving.

### 3.1 Core

**`admin_users`** — email, password_hash, name, role, is_active, last_login_at

**`event_templates`** `[A-1]`, `[A-2]` — name, default JSONB payload for grade, duration, inclusions, exclusions, things-to-carry, safety guidelines. New events copy from a template, then diverge freely.

**`events`** `[A-1]`, `[A-9]`
- name, slug (unique, URL-safe), region, base_village
- grade (`easy` | `easy_moderate` | `moderate` | `difficult`)
- duration_label, start_datetime, end_datetime
- capacity `[A-4]`, price, payment_model (`full` | `advance`), advance_amount `[A-7]`
- status (`draft` | `published` | `archived`), published_at
- banner_image_id
- Multiple events may share a date `[A-9]` — no unique constraint on date.

**`event_content`** `[A-24]`, `[P-11]` — one row per event: trek_history, key_attractions (JSONB list), inclusions, exclusions, things_to_carry, safety_guidelines, faqs (JSONB list), latest_update (text + timestamp). Kept separate from `events` so content edits don't lock the row used for seat counting (§5.1).

**`event_images`** `[A-3]` — event_id, storage_key, alt_text, sort_order, is_banner

**`itinerary_stages`** `[A-11]` — event_id, time_label, title, description, sort_order

**`itinerary_versions`** — SRS §02 recommendation. Snapshot JSONB written on every publish-time change, with the admin who made it. Drives "version history" and the change-notification trigger.

### 3.2 Transport

**`bus_routes`** `[A-23]`, SRS §04 change
- event_id, name, vehicle_registration, vehicle_capacity, driver_name, driver_phone
- **`vehicle_capacity` is a hard ceiling** — bookings assigned to a route must never exceed it, enforced the same way seat capacity is (§5.1).

**`bus_stops`** — route_id, time_label, point_name, landmark, latitude, longitude, sort_order

`latitude`/`longitude` support the interactive pickup map (SRS §02 recommendation). Nullable — the map is a later phase, the fields are cheap now.

### 3.3 People and bookings

**`participants`** `[A-14]` — master list, deduplicated
- full_name, phone (indexed), email (indexed), city, date_of_birth, tshirt_size
- `duplicate_of_id` — self-referencing FK, set by the detection job
- Dedup rule: exact phone match, or exact email match, or fuzzy name match (trigram ≥ 0.85) combined with matching city. Flag, never auto-merge — merging is an explicit admin action.

**`registrations`** — the booking
- event_id, participant_id, seat_number, boarding_stop_id
- status: `pending_payment` | `confirmed` | `cancelled` | `refunded` | `waitlisted`
- payment_model, amount_due, amount_paid
- idempotency_key (unique, indexed) — see §5.2
- seat_lock_expires_at — 10-minute hold, matches the prototype's "seat held 10 min"
- tnc_accepted_at, tnc_version — SRS §03
- source (UTM/referral tagging, for the KPI framework §6)

**`medical_declarations`** — SRS §05 Critical
- registration_id, conditions, allergies, medications, fitness_declared_at
- **Encrypt at rest.** This is health data under the DPDP Act. Application-level encryption (Fernet or pgcrypto), key in the secret store, never in the repo. Readable only by `owner` and `event_manager`; excluded from every export except the trek-lead manifest.

**`emergency_contacts`** — registration_id, name, phone, relationship. Mandatory.

**`guardian_consents`** — SRS §05 Critical
- registration_id, guardian_name, guardian_phone, relationship, consent_given_at
- **Required whenever participant age < 18 at trek start date.** Reject the registration with `422` if absent. The prototype branches the form automatically on age entry — the backend must enforce it independently, never trusting the client.

**`identity_documents`** — registration_id, storage_key, mime_type, uploaded_at. Optional field, PDF/JPEG only, 5 MB cap. Encrypted at rest, private bucket, pre-signed URLs with short expiry. Purge on the retention schedule (§7).

### 3.4 Money

**`payments`**
- registration_id, amount, type (`advance` | `full` | `balance` | `manual`)
- method (`upi` | `qr` | `cash_to_volunteer` | `upi_to_volunteer` | `bank_transfer`)
- razorpay_order_id, razorpay_payment_id, razorpay_signature
- status (`created` | `captured` | `failed`)
- collected_by_admin_id, collected_note — for manual collection (§5.5)
- gst_invoice_number — SRS §05 Critical

**`refunds`** `[A-6]` — payment_id, amount (supports partial), reason, initiated_by_admin_id, razorpay_refund_id, status, completed_at

**`webhook_events`** — raw Razorpay payloads with a processed flag. Never process a webhook twice; never trust a client redirect as proof of payment (SRS §04 change to #22).

### 3.5 Waitlist, comms, audit

**`waitlist_entries`** `[A-4]`, `[A-5]`
- event_id, participant_id, position, joined_at
- state: `waiting` | `promoted` | `converted` | `expired` | `withdrawn`
- promoted_at, **sla_expires_at** — 24 hours (SRS §04 change to #5)

**`notifications`** — SRS §05 Important
- participant_id, channel (`whatsapp` | `sms` | `email`), template_key, payload JSONB
- status (`queued` | `sent` | `delivered` | `failed`), failure_reason
- **`opt_in_consent`** captured at registration — required under WhatsApp Business policy. SMS fallback fires when WhatsApp delivery fails or the participant has opted out.

**`audit_log`** — SRS §05 Important
- admin_user_id, action, entity_type, entity_id, before JSONB, after JSONB, ip_address
- Write on: publish, capacity change, price change, refund, manual payment, waitlist promotion, participant data edit, role change. Append-only — no updates, no deletes.

---

## 4. API surface

Grouped by the prototype screen each one serves.

### Public — participant portal (no auth)

```
GET    /api/v1/public/events                    # published only, seats_left computed
GET    /api/v1/public/events/{slug}             # full detail: content, itinerary, routes, gallery, FAQs
GET    /api/v1/public/reviews                   # approved testimonials only
POST   /api/v1/public/registrations             # idempotency-key header required
POST   /api/v1/public/lookup/request-otp
POST   /api/v1/public/lookup/verify-otp         # returns scoped token
GET    /api/v1/public/bookings                  # scoped token; that phone's bookings
POST   /api/v1/public/bookings/{id}/pay-balance
POST   /api/v1/public/bookings/{id}/cancel      # SRS §05 Important — self-service cancellation
POST   /api/v1/public/waitlist                  # join when full
POST   /api/v1/webhooks/razorpay                # signature-verified, idempotent
```

`GET /public/events` and `/public/events/{slug}` are the hot path — the Next.js pages server-render from them. Target p95 under 200 ms; cache in Redis with invalidation on publish.

### Admin

```
POST   /api/v1/auth/login  /refresh  /logout

GET    /api/v1/events                           # filter, sort, search [A-18]
POST   /api/v1/events                           # from template [A-1]
GET    /api/v1/events/{id}
PATCH  /api/v1/events/{id}
POST   /api/v1/events/{id}/publish              # triggers notify if bookings exist
POST   /api/v1/events/{id}/archive
PATCH  /api/v1/events/{id}/capacity             # audited; cannot go below confirmed count

PUT    /api/v1/events/{id}/content              # [A-24] trek history, attractions, FAQs, safety
PUT    /api/v1/events/{id}/itinerary            # [A-11] full-list replace, versioned
GET    /api/v1/events/{id}/itinerary/versions
POST   /api/v1/events/{id}/images               # [A-3] multipart
PUT    /api/v1/events/{id}/form-fields          # [A-21] dynamic registration form config

GET    /api/v1/events/{id}/routes               # [A-23]
POST   /api/v1/events/{id}/routes
PATCH  /api/v1/routes/{id}
PUT    /api/v1/routes/{id}/stops
POST   /api/v1/routes/publish-and-notify        # immediate participant-side effect

GET    /api/v1/events/{id}/participants         # per-event roster
GET    /api/v1/participants                     # global master list [A-10], [A-14]
GET    /api/v1/participants/duplicates
POST   /api/v1/participants/{id}/merge

GET    /api/v1/events/{id}/waitlist
POST   /api/v1/waitlist/{id}/promote            # single
POST   /api/v1/waitlist/promote-bulk            # bulk, capacity-aware [A-5]

GET    /api/v1/payments
POST   /api/v1/payments/request-balance         # [A-8] single or bulk, WhatsApp links
POST   /api/v1/payments/manual                  # cash/UPI collected by volunteer
POST   /api/v1/refunds                          # [A-6] full or partial

GET    /api/v1/analytics/kpis                   # [A-13] — §6
GET    /api/v1/analytics/funnel
GET    /api/v1/analytics/profit                 # [A-17] business profit calculator
GET    /api/v1/exports/participants             # [A-12] CSV
GET    /api/v1/exports/bus-manifest             # per route, grouped by stop

GET    /api/v1/reviews                          # [A-19] moderation queue
PATCH  /api/v1/reviews/{id}                     # publish | hide

GET    /api/v1/audit-log                        # owner only
```

---

## 5. Business rules

These are the rules that cost the most to retrofit. Each needs a test.

### 5.1 Last-seat race condition `[A-16]`, SRS §04

**Never** read seat count, then write a booking, as two statements. Inside one transaction:

```python
event = await session.execute(
    select(Event).where(Event.id == event_id).with_for_update()
)
if confirmed_count >= event.capacity:
    raise SeatUnavailable()
```

Same pattern for `bus_routes.vehicle_capacity` — assigning a boarding point locks the route row. Overbooking a bus is the same class of bug as overbooking a trek and gets the same treatment.

Write a concurrency test: 50 simultaneous requests for the last seat must yield exactly 1 confirmation and 49 clean rejections.

### 5.2 Idempotency

Every booking and payment request carries an `Idempotency-Key` header. Store it; on repeat, return the original response rather than creating a second record. Razorpay retries webhooks — double-charging or double-booking a participant is unacceptable.

### 5.3 Seat hold

On registration, hold the seat for **10 minutes** (`seat_lock_expires_at`). A Celery beat task releases expired holds every minute. The prototype tells the participant "seat held 10 min" — honour it exactly.

### 5.4 Waitlist SLA `[A-5]`, SRS §04

On promotion: set `sla_expires_at = now + 24h`, send the WhatsApp payment link, fall back to SMS on delivery failure. A Celery task expires unpaid promotions, returns the seat to the pool, and promotes the next person in position order.

**Bulk promotion is capacity-aware.** If 7 are selected and 5 seats exist, promote 5 in position order and report that 2 could not fit — do not silently over-promote. This is exactly what the prototype does.

### 5.5 Manual payment collection

A participant may hand cash to a volunteer instead of paying a link. `POST /payments/manual` records amount, mode, collecting admin, and note. Rules:

- Amount cannot exceed the outstanding balance.
- The entry is **immutable** — corrections happen through a refund, never an edit.
- Always writes to `audit_log`.
- Recalculates the participant's balance, the event's collected total, and every dependent KPI immediately.

### 5.6 Publish and change notification

Publishing a **new** event notifies nobody. Changing an **already-published** event's itinerary or bus routes notifies every confirmed participant on WhatsApp (SMS fallback), and writes an itinerary/route version entry. `[A-23]` requires participant-portal changes to be immediate — no cache lag on published event content.

### 5.7 Refunds `[A-6]`

Full or partial. Policy from the prototype's FAQ: full refund up to 7 days before, 50% up to 72 hours, none after. **Compute the eligible amount server-side and return it**; the admin may override it, and the override is audited. Refund to source, 5-working-day SLA, GST-compliant credit note.

---

## 6. Analytics `[A-13]` — SRS §06

Every metric below must be derivable from day one. If a field a metric needs isn't being captured, capture it now — this is the cheapest it will ever be.

**Revenue** — gross and net-of-refunds by event and date range; average booking value; advance vs full split; refund rate; balance collection rate.

**Occupancy** — seat occupancy % per event; waitlist size; waitlist-to-paid conversion; time-to-sell-out.

**Funnel** — event view → form started → payment completed. **Requires the frontend to post view and form-start events** — expose `POST /api/v1/public/track` (fire-and-forget, no PII). Also cancellation rate, average booking-to-cancellation time, repeat participant rate (matched on phone/email, since there are no accounts), and promotion-notice → payment-received time.

**Growth** — MoM and season-over-season trends; bookings by source (requires UTM capture on the landing page, stored on `registrations.source`); average review rating per trek.

**Operations** — bus route utilisation %; waitlist promotion → payment time; event publish → first booking.

Serve these from pre-aggregated tables refreshed by a Celery beat job, not from live queries across the full booking history.

---

## 7. Security, privacy, compliance

SRS §05 Critical — treat as blocking, not backlog.

- **PII and medical data encrypted at rest.** Medical declarations and ID documents get application-level encryption on top of disk encryption.
- **DPDP Act alignment.** Purpose limitation, a stated retention policy, and a deletion path. Default retention: medical declarations and ID documents purged 90 days after trek completion; booking and payment records retained 7 years for tax.
- **Consent is recorded, not assumed.** T&C version and timestamp per registration; WhatsApp opt-in captured explicitly.
- **Rate limiting** on OTP request, OTP verification, and registration.
- **Razorpay webhooks** verified by signature. Reject unsigned payloads.
- **No secrets in the repo.** Environment variables, `.env.example` documents the shape only.
- **CORS** restricted to the Vercel production domain, the `development` preview domain, and localhost.
- **Multi-tenancy:** single tenant for now. Do not build tenant isolation, but do not hard-code assumptions that block it — keep a nullable `organisation_id` on `events` and `admin_users`.

---

## 8. Non-functional targets

SRS §05 flags these as entirely absent. Baselines:

| Target | Value |
|---|---|
| Public event endpoints | p95 < 200 ms |
| Admin list endpoints | p95 < 500 ms |
| Booking spike | 200 concurrent registrations on one event without a lost or duplicated seat |
| Payload size | public event detail < 100 KB JSON — participants book on patchy mobile networks |
| Uptime | 99.5% |
| Backups | daily automated, 30-day retention, restore tested quarterly |
| Test coverage | ≥ 80% on `services/`; 100% on seat-locking, payment and refund paths |

---

## 9. Build order

Ship in slices that can be run and reviewed. Do not attempt the whole backend in one pass.

1. **Foundation** — project scaffold, config, DB session, Alembic, health check, admin auth with roles, audit log.
2. **Events** — templates, CRUD, publish/archive, content, itinerary with versioning, images. Public read endpoints.
3. **Bus routes** — routes, stops, vehicle capacity enforcement, publish-and-notify.
4. **Registrations** — dynamic form config, participant dedup, medical and emergency data, guardian branch, **seat locking**, idempotency, seat holds.
5. **Payments** — Razorpay orders, webhooks, advance/full, balance requests, manual collection, refunds, GST invoicing.
6. **Waitlist** — join, position, single and bulk promotion, 24-hour SLA expiry, auto-promotion.
7. **Notifications** — WhatsApp templates, SMS fallback, opt-in enforcement, delivery logging.
8. **Analytics and exports** — KPI aggregation, funnel tracking, CSV exports, bus manifest.
9. **Reviews** — submission, moderation queue, public listing.

Each slice: models + migration + schemas + service + router + tests, in one PR into `development`.

---

## 10. Deliverables per PR

- Alembic migration, both `upgrade` and `downgrade`
- Tests covering the happy path and every failure mode named in §5
- Updated `.env.example` for any new configuration
- OpenAPI descriptions on every endpoint — the frontend generates its client from this
- No `TODO` comments in merged code; open an issue instead

---

## 11. Open questions for the client

Do not block on these — implement the stated default and flag it.

1. **GST registration number and invoice series format** — needed for compliant invoicing. Default: sequential `TMC/26-27/0001`.
2. **Refund policy confirmation** — the 7-day / 72-hour tiers come from the prototype FAQ, not the SRS. Confirm before going live.
3. **WhatsApp Business API provider** — affects the integration adapter. Default: build behind an interface so the provider can be swapped.
4. **Coupon and referral system** (SRS §05 Important) — deferred. Confirm it is out of scope for v1.
5. **Group and corporate booking** (SRS §05 Important) — deferred. Confirm.
6. **Guide and vehicle assignment per event** (SRS §05 Important) — partially covered by `bus_routes` driver fields. Confirm whether per-event staff rostering is needed in v1.
