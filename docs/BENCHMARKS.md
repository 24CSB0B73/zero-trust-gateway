# Benchmarks

Numbers depend entirely on hardware, so **measure on your machine and paste the results below**; quote them with the
hardware spec. A sandbox smoke run (shared cores, Python load generator) reached ~350 req/s at ~45 ms mean latency —
that is a client- and CPU-bound figure, **not** a benchmark.

## What each protected request costs
JWT verify (HMAC) → session+user lookup (1 query) → policy (cache hit: 0 queries) → device lookup (1 query, only if required) →
**audit INSERT (1 query + commit)** → proxy hop to the upstream → session re-check (1 query). The synchronous audit commit is the
dominant cost; see "Tuning" for the trade-off.

## Method
1. Raise the limiter so you measure the gateway, not the limiter: `RATE_RPS=1000000 RATE_BURST=1000000` (compose: put them in `.env`).
2. Warm up 10 s, then measure 30–60 s, three runs, report the median.
3. Scenarios: **A** public resource (no device) · **B** device-required resource · **C** denied request (role mismatch) · **D** login (PBKDF2-bound).
4. Tools (pick one):
   * `python3 tools/bench.py --threads 16 --seconds 30` (stdlib, simple, client-limited)
   * `wrk -t4 -c64 -d30s -H "Authorization: Bearer $TOKEN" http://localhost:8080/resources/3`
   * `hey -z 30s -c 64 -H "Authorization: Bearer $TOKEN" http://localhost:8080/resources/3`
   * Get `$TOKEN` from `/auth/login` as admin; admin may use all three demo resources (add `-H "X-Device-Id: ..."` for B).
5. Watch `GET /metrics` (`zt_request_seconds_sum / _count`, cache hit rate) and `docker stats`.

## Results (fill in)
| Date | CPU / RAM / OS | Scenario | Threads | req/s | p50 ms | p95 ms | p99 ms | Errors |
|---|---|---|---|---|---|---|---|---|
| | | A public | | | | | | |
| | | B device | | | | | | |
| | | C denied | | | | | | |
| | | D login | | | | | | |

## Tuning knobs worth experimenting with (and writing up)
* `THREADS` / `POOL_SIZE` — find the knee where more threads stop helping.
* PostgreSQL `synchronous_commit=off` for the audit connection: large throughput gain, but a crash can lose the last few hundred ms of audit rows — an explicit security trade-off, say so.
* Batching audit rows through a bounded in-memory queue (and failing closed when the queue is full).
* Short-TTL session-status cache with explicit invalidation (trades revocation immediacy for fewer queries).
* Scenario C vs A shows how cheap denial is — denied requests skip the upstream entirely.
