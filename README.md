# Zero Trust Access Gateway (C++17 · PostgreSQL)

A reverse-proxy access gateway built on one rule: **being "inside the network" grants nothing.**
Every request to a protected application is authenticated, then authorized against a resource
policy that looks at *who* the user is, *what role* they hold, *what device* they are on, and
whether that device is *currently healthy*. If any of that cannot be established, the answer is **deny**.

```
 Client (browser / curl)
        │  Authorization: Bearer <JWT>     X-Device-Id: <device>
        ▼
 ┌──────────────────────────── C++ Access Gateway ────────────────────────────┐
 │ rate limit → authenticate → load policy → evaluate → audit → forward → re-check │
 │   (per IP)    (JWT + live    (cache,       (role +    (fail    (timeouts)  (revoked │
 │                session/acct)  invalidated)  device)    closed)             mid-flight?)│
 └───────┬──────────────────────────┬──────────────────────────┬──────────────┘
         │                          │ deny → 403, app never sees it
         ▼                          ▼
   PostgreSQL                 Protected demo apps (hr-portal, finance-reports, public-wiki)
   users · sessions · roles   — on an internal-only Docker network, no published ports —
   policies · devices · audit
```

## What it demonstrates

| Concern | Where | Proof |
|---|---|---|
| Authenticated ≠ authorized | `src/policy.cpp` (pure `evaluate()`, default deny) | `PolicyEngine.*` unit tests, integration 11–17 |
| Untrusted client posture | `h_attest` — HMAC-signed reports, ±60 s clock window, replay rejection | integration 13, 14 |
| Instant revocation | session + account re-read from DB **every request**, plus a post-forward re-check | integration 23–25, 32, 33 |
| Concurrency safety | thread pool, DB connection pool, `shared_mutex` policy cache with generation counter | `PolicyCache.*` tests, integration 33, **ThreadSanitizer: 0 warnings** |
| Brute-force & abuse | token-bucket rate limiter, per-account login lockout, constant-time login | `RateLimiter.*`, `LoginThrottle.*`, integration 26, 34 |
| Injection | `PQexecParams` only (no string-built SQL), allow-list validation | integration 04 |
| Token attacks | HS256 only (blocks `alg:none`), signature before claims, role read from DB not token | `Jwt.*`, integration 20–22 |
| Failure handling | upstream timeouts, 502 without internals, **no audit write ⇒ no access** | integration 30–32 |

## The 22-item checklist

| Phase | Item | Status / location |
|---|---|---|
| 1 | Project structure, Git, CMake | `CMakeLists.txt`, `.gitignore` |
| 1 | HTTP server + REST endpoints | `src/gateway.cpp` (cpp-httplib) |
| 1 | Protected demo application | `demo/demo_service.cpp` |
| 2 | Register + secure password hashing | PBKDF2-HMAC-SHA256, 210k iters, random salt — `src/crypto.cpp` |
| 2 | Login + short-lived JWT | HS256, 15-minute `exp`, `jti` bound to a DB session |
| 2 | Logout, expiry, account status | `Gateway::authenticate`, `/auth/logout`, `/admin/users/:id/disable` |
| 3 | RBAC | `users.role`, `policies.allowed_roles` |
| 3 | Resource-level policy engine | `src/policy.cpp` |
| 3 | Identity + device posture + request context | `evaluate()`; device from `X-Device-Id` + signed attestation |
| 3 | Default deny | no policy / inactive / unknown resource / any failure ⇒ 403 |
| 4 | PostgreSQL for users, roles, resources, policies | `db/schema.sql` (roles are a column + `text[]`; normalize later if needed) |
| 4 | Audit logs for allow **and** deny | `audit_logs`, written *before* forwarding |
| 4 | Login throttling + API rate limiting | `src/limits.hpp` |
| 4 | Input validation + parameterized SQL | `src/gateway.cpp`, `src/db.cpp` |
| 5 | Concurrent request handling | 32-thread pool, 16-connection DB pool |
| 5 | Timeouts + safe errors | DB `statement_timeout`, pool-wait 3 s, upstream 2 s/5 s, generic 5xx bodies |
| 5 | Policy cache with invalidation | `PolicyCache` (TTL 30 s + explicit invalidate on policy change) |
| 5 | Test revocation / concurrency / failures | `tests/integration_test.py` 23–34 |
| 6 | Docker | `Dockerfile`, `docker-compose.yml` |
| 6 | Unit + integration tests | 27 GoogleTest cases + 25 end-to-end tests |
| 6 | Metrics + security dashboard | `GET /metrics` (Prometheus text), `/ui/dashboard.html` |
| 6 | Architecture, threat model, benchmarks | `docs/` |

## Quick start (Docker — recommended)

Prerequisites: Docker Desktop (WSL2 backend on Windows), Git, Python 3. Full step-by-step: [docs/SETUP.md](docs/SETUP.md).

```bash
cp .env.example .env            # then edit: JWT_SECRET, ADMIN_PASSWORD, DB_PASSWORD
docker compose up --build -d
curl http://localhost:8080/healthz
```

Open **http://localhost:8080/** → dashboard (sign in as the admin). Then run the narrated demo:

```bash
ADMIN_PASSWORD='<your .env value>' python3 tools/demo.py
```

## Build from source (Linux / WSL2)

```bash
sudo apt install -y build-essential cmake ninja-build git libpq-dev libssl-dev postgresql python3
cmake -G Ninja -B build && cmake --build build      # downloads httplib, nlohmann/json, GoogleTest
./build/unit_tests
```

Run it (PostgreSQL must be up; see docs/SETUP.md §B for creating the DB):

```bash
export JWT_SECRET=$(python3 -c "import secrets;print(secrets.token_hex(32))")
export ADMIN_EMAIL=admin@example.com ADMIN_PASSWORD='Admin-Password-123!'
export DATABASE_URL=postgresql://zt:zt@127.0.0.1:5432/ztgw DEMO_UPSTREAM=http://127.0.0.1:9000 WEB_DIR=$PWD/web
./build/demo_service &  ./build/gateway
```

## Configuration (environment variables)

| Variable | Default | Meaning |
|---|---|---|
| `JWT_SECRET` | *(required, ≥32 chars)* | HMAC key for tokens. Gateway refuses to start without it. |
| `DATABASE_URL` | `postgresql://zt:zt@127.0.0.1:5432/ztgw` | libpq connection string |
| `ADMIN_EMAIL` / `ADMIN_PASSWORD` | – | First admin, created at startup if absent |
| `DEMO_UPSTREAM` | – | If set and no resources exist, seeds 3 demo resources + policies |
| `PORT` | 8080 | Listen port |
| `JWT_TTL_SEC` | 900 | Access-token lifetime |
| `THREADS` / `POOL_SIZE` | 32 / 16 | HTTP worker threads / DB connections |
| `RATE_RPS` / `RATE_BURST` | 50 / 100 | Per-IP token bucket (all endpoints) |
| `LOGIN_RPS` / `LOGIN_BURST` | 2 / 20 | Per-IP bucket on `/auth/login` (protects PBKDF2 CPU) |
| `POLICY_TTL_SEC` | 30 | Policy cache TTL (invalidation is immediate on change) |
| `PBKDF2_ITERS` | 210000 | Hashing cost for new passwords (lower only for tests) |

## API

| Method | Endpoint | Auth | Purpose |
|---|---|---|---|
| POST | `/auth/register` | – | Create user (role is always `employee`) |
| POST | `/auth/login` | – | Issue 15-min JWT bound to a server-side session |
| POST | `/auth/logout` | user | Revoke this session |
| GET | `/resources` | user | Resources the caller's *role* may use |
| GET | `/resources/:id` | user (+ `X-Device-Id`) | **Enforcement point**: authn → policy → audit → proxy |
| POST | `/device/attest` | user | Submit HMAC-signed posture report |
| POST | `/policies` | admin | Create/replace a resource policy (invalidates cache) |
| POST | `/resources` | admin | Register a protected upstream |
| GET | `/audit-logs?limit&decision&email&reason` | admin | Access history |
| POST | `/admin/devices` | admin | Enroll a device (returns its secret once) |
| POST | `/admin/users/:id/{disable,enable,revoke-sessions,role}` | admin | Account control |
| GET | `/metrics` | admin | Prometheus text metrics |
| GET | `/healthz` | – | Liveness + DB check |

```bash
# manual walk-through
curl -s -XPOST localhost:8080/auth/register -d '{"email":"bob@example.com","password":"a-long-password-1"}'
TOKEN=$(curl -s -XPOST localhost:8080/auth/login -d '{"email":"bob@example.com","password":"a-long-password-1"}' | python3 -c "import sys,json;print(json.load(sys.stdin)['access_token'])")
curl -s localhost:8080/resources -H "Authorization: Bearer $TOKEN"
curl -s -i localhost:8080/resources/1 -H "Authorization: Bearer $TOKEN"        # 403: hr-portal needs a device
```

## Tests

```bash
./build/unit_tests                                    # 27 unit tests (crypto, JWT, policy, cache, limiters)

# end-to-end (gateway + demo + postgres running; env = same values the gateway uses)
JWT_SECRET=... ADMIN_EMAIL=... ADMIN_PASSWORD=... python3 tests/integration_test.py -v
# if the gateway runs in Docker, also: DEMO_UPSTREAM=http://demo:9000

# race detection
cmake -G Ninja -B build-tsan -DZT_SANITIZE=thread && cmake --build build-tsan
./build-tsan/unit_tests && PORT=8081 ./build-tsan/gateway     # then run the integration tests with GATEWAY_URL=http://127.0.0.1:8081
```

## Documentation

* [docs/SETUP.md](docs/SETUP.md) — every tool and step to run this on your PC
* [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — request lifecycle, concurrency model, data model
* [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) — assets, attackers, mitigations, known limits
* [docs/BENCHMARKS.md](docs/BENCHMARKS.md) — how to measure, with a table to fill in on *your* hardware

## Known limitations (be upfront about these in an interview)

* **No TLS inside the gateway.** Terminate TLS in front (nginx/Caddy/cloud LB) or add OpenSSL listeners. Tokens over plain HTTP are only acceptable on localhost.
* **HS256 is symmetric**: every verifier can mint tokens. Production: RS256/ES256 with a JWKS endpoint, or an external IdP (OIDC).
* **Device attestation is simulated** with a per-device HMAC secret. Real systems use hardware-backed keys (TPM / Secure Enclave) and an EDR/MDM agent.
* **Rate limiter and login throttle are per-process memory.** Multiple gateway replicas need Redis or sticky routing. `X-Forwarded-For` is deliberately not trusted.
* **Session lookup on every request** costs a DB round trip but is what gives instant revocation. The alternative (stateless JWT + short TTL + revocation list cache) trades immediacy for speed.
* **Policy cache across replicas** relies on the 30 s TTL as a staleness bound; use PostgreSQL `LISTEN/NOTIFY` to invalidate across instances.
