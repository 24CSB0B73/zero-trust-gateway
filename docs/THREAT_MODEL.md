# Threat model

**Assets:** protected applications and their data; user credentials; session tokens; policy integrity; audit trail integrity.
**Trust boundaries:** Internet/LAN → gateway; gateway → PostgreSQL; gateway → upstream apps; device agent → gateway.
**Assumptions:** TLS is terminated in front of the gateway in any real deployment; the host and the DB are not compromised;
`JWT_SECRET` and device secrets stay secret.

## STRIDE-style table
| # | Threat | Mitigation | Evidence |
|---|---|---|---|
| T1 | Spoofing: forged / edited JWT, `alg:none`, wrong key | HS256-only, constant-time signature check *before* reading claims, `iss` check | `Jwt.*`, integration 21 |
| T2 | Spoofing: stolen/old token after logout, disable, revoke | Server-side session checked every request; post-forward re-check | integration 23, 24, 32, 33 |
| T3 | Spoofing: expired token replay | `exp` enforced in token **and** `sessions.expires_at` in DB | `Jwt.ExpiredRejected`, integration 20 |
| T4 | Elevation: client picks own role / role claim tampering | Role forced to `employee` on register; role read from DB per request | integration 03, 22, 25 |
| T5 | Elevation: authenticated user hits resource outside policy | Resource-level policy, default deny | integration 15–17 |
| T6 | Tampering: client lies about device health | Signed posture, ownership check, freshness, replay protection | integration 13, 14 |
| T7 | Tampering: SQL injection | `PQexecParams` everywhere; allow-list validation of every input | integration 04 |
| T8 | Repudiation: "I never accessed that" | Audit row for every allow/deny/error with reason, IP, user; written before forwarding | integration 11–17 |
| T9 | Info disclosure: user/resource enumeration | Uniform 401; unknown resource == forbidden (403); login runs PBKDF2 even for unknown users | integration 17 |
| T10 | Info disclosure: stack traces / internals | Generic error bodies; details only in server log/audit | integration 30 |
| T11 | Info disclosure: bearer token leaks to upstream | Token stripped; `X-ZT-*` identity headers instead | `h_access_resource` |
| T12 | DoS: brute force / credential stuffing | Per-account lockout (5/5 min), per-IP login bucket, generic failure message | integration 26 |
| T13 | DoS: request flood | Per-IP token bucket; 64 KB body cap; read/write timeouts; bounded pools | integration 34 |
| T14 | DoS: slow or dead upstream pins threads | 2 s connect / 5 s read timeouts → 502 | integration 30, 31 |
| T15 | DoS: DB stall | `statement_timeout` 3 s; 3 s pool-acquire timeout → 503 (fail closed) | `db.cpp` |
| T16 | Cache poisoning: stale policy after admin change | Invalidate after commit + generation counter | `PolicyCache.*`, integration 16 |
| T17 | Lateral movement: bypass gateway, hit apps directly | Docker `internal` network, no published ports for apps/DB | docker-compose.yml |
| T18 | XSS in dashboard via attacker-controlled emails | `textContent` only; CSP `default-src 'self'` | `web/dashboard.js` |
| T19 | Container breakout hardening | Non-root user, read-only FS, all capabilities dropped, no-new-privileges | Dockerfile / compose |
| T20 | Admin lockout by mistake | Admin cannot disable own account | `h_user_status` |

## Out of scope / residual risk (honest list)
* Transport security (TLS/mTLS) — add a TLS-terminating proxy; mTLS to upstreams is the natural next step.
* Compromised `JWT_SECRET` ⇒ attacker can mint tokens, but still needs a live session row (`jti`) to pass step 2 — a real mitigation worth noting, not a substitute for rotating the key.
* Per-account lockout allows an attacker to lock a victim out (classic trade-off); per-IP limits and monitoring are the usual compensation.
* Device secrets sit in the DB in plaintext (demo). Production: hardware-backed keys, asymmetric signatures, envelope encryption.
* In-memory limiter state is per process and reset on restart.
* No refresh-token flow, MFA, or SSO/OIDC integration.
