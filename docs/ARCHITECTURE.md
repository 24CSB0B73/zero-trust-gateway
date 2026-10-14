# Architecture

## Components
* **Gateway (C++17)** — cpp-httplib server (thread pool), libpq connection pool, OpenSSL for PBKDF2/HMAC.
  * `crypto.*` password hashing, HS256 JWT, HMAC, constant-time compare
  * `policy.*` pure policy evaluation + concurrent policy cache
  * `limits.hpp` token-bucket limiter, login throttle
  * `db.*` connection pool, parameterized queries only
  * `gateway.*` routing, authn pipeline, audit, proxy, admin APIs
* **PostgreSQL** — source of truth for identities, sessions, policies, device state, audit.
* **Demo apps** — stand-ins for internal services. In Docker they sit on an `internal: true` network.

## Request lifecycle — `GET /resources/:id`
1. **Per-IP rate limit** (pre-routing). Over budget → 429.
2. **Authenticate**: parse bearer token → verify HS256 signature → check `exp` → look up `jti` in `sessions` joined with `users`. Rejects: missing, malformed, bad signature, expired, unknown session, **revoked**, **disabled account**. Every failure returns the same `401` (no oracle); the *precise* reason goes to the audit log.
3. **Load resource + policy** from `PolicyCache` (miss → one DB read outside any lock).
4. **Collect context**: the user's *current* role (from DB, never the token) and, if the policy requires it, the device record for `X-Device-Id`.
5. **Evaluate** (`evaluate()`): account active → policy exists → policy active → role permitted → device enrolled → owned by caller → healthy → report fresh. First failing check wins; reaching the end is the *only* way to allow.
6. **Audit before forward.** If the audit row cannot be written the request is refused (503): *no record, no access*.
7. **Forward** to the upstream with 2 s connect / 5 s read timeouts. The bearer token is **not** forwarded; identity is passed as `X-ZT-*` headers.
8. **Re-validate** the session after the upstream answers. If it was revoked while the request was in flight, the response is discarded (`revoked_during_request`).

Denied requests (steps 1–5) never open a connection to the upstream.

## Concurrency model
| Shared state | Protection | Why it is safe |
|---|---|---|
| HTTP workers | 32-thread pool | Handlers hold no mutable globals |
| DB connections | mutex + condvar pool, 3 s acquire timeout | A connection is owned by exactly one query at a time; pool exhaustion fails closed (503) |
| Policy cache | `shared_mutex` (many readers, one writer) + **generation counter** | Loader reads the DB *outside* the lock and only publishes if no invalidation happened meanwhile, so a slow reader can never write stale policy back after an admin change |
| Rate limiter / throttle | one mutex each, O(1) work under lock | Bounded critical sections; memory capped at 100k keys |
| Metrics | one mutex around a map | counters only |
| Sessions / users | **not cached** | Revocation is a single `UPDATE`; the very next request sees it (read-committed) |

Invariant tested in `test_33`: *no request that **starts** after a revocation call returns may succeed*; requests already
past authentication can finish, but step 8 withholds their response if the session died meanwhile.

## Data model
`users(role, active)` · `resources(upstream_url)` · `policies(resource_id UNIQUE, allowed_roles text[], require_healthy_device, max_posture_age_sec, active)` ·
`sessions(id=jti, expires_at, revoked)` · `devices(id, user_id, secret)` · `device_status(healthy, details, last_report_ts, last_check)` ·
`audit_logs(user_id, email, resource_id, action, decision, reason, ip)` (no FKs: logs outlive their subjects).

## Device posture trust
Clients cannot assert health. A report `{device_id, ts, os_patched, disk_encrypted, firewall_on, antivirus_on}` must carry
`HMAC-SHA256(device_secret, "device_id|ts|0/1 bits")`. The secret is created at admin enrollment (simulating MDM provisioning).
The gateway also requires: device belongs to the authenticated user, `|now − ts| ≤ 60 s`, and `ts` strictly greater than the last
accepted report (replay protection). A posture is trusted only for `max_posture_age_sec` (default 15 min).

## Why not stateless JWTs only?
Pure stateless validation can't honour "revoke now". This design keeps the JWT as a signed *session handle* and spends one indexed
DB lookup per request to get immediate revocation, account-disable and live role changes. If that cost matters, the documented
next step is a short-TTL positive cache of session status with explicit invalidation (like the policy cache).
