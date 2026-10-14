#!/usr/bin/env python3
"""Tiny load generator (stdlib only). For serious numbers use `wrk` or `hey` (see README).

Start the gateway with the per-IP limiter effectively off, otherwise you benchmark the limiter:
    RATE_RPS=1000000 RATE_BURST=1000000 ./gateway
  ADMIN_EMAIL=... ADMIN_PASSWORD=... python3 tools/bench.py --threads 16 --seconds 10
"""
import argparse
import http.client
import json
import os
import statistics
import threading
import time
import urllib.parse

ap = argparse.ArgumentParser()
ap.add_argument("--base", default=os.environ.get("GATEWAY_URL", "http://127.0.0.1:8080"))
ap.add_argument("--threads", type=int, default=16)
ap.add_argument("--seconds", type=int, default=10)
ap.add_argument("--resource", default="public-wiki")
a = ap.parse_args()
u = urllib.parse.urlparse(a.base)


def req(conn, method, path, body=None, token=None):
    h = {"Content-Type": "application/json"}
    if token:
        h["Authorization"] = "Bearer " + token
    conn.request(method, path, json.dumps(body) if body is not None else None, h)
    r = conn.getresponse()
    return r.status, r.read()


c = http.client.HTTPConnection(u.hostname, u.port)
s, raw = req(c, "POST", "/auth/login", {"email": os.environ["ADMIN_EMAIL"], "password": os.environ["ADMIN_PASSWORD"]})
token = json.loads(raw)["access_token"]
_, raw = req(c, "GET", "/resources", token=token)
rid = {r["name"]: r["id"] for r in json.loads(raw)["resources"]}[a.resource]
path = f"/resources/{rid}"

lat, codes, lock = [], {}, threading.Lock()
end = time.time() + a.seconds


def worker():
    conn = http.client.HTTPConnection(u.hostname, u.port)
    mine, my_codes = [], {}
    while time.time() < end:
        t0 = time.perf_counter()
        st, _ = req(conn, "GET", path, token=token)
        mine.append(time.perf_counter() - t0)
        my_codes[st] = my_codes.get(st, 0) + 1
    with lock:
        lat.extend(mine)
        for k, v in my_codes.items():
            codes[k] = codes.get(k, 0) + v


ths = [threading.Thread(target=worker) for _ in range(a.threads)]
t0 = time.time()
[t.start() for t in ths]
[t.join() for t in ths]
dur = time.time() - t0
lat.sort()
pct = lambda p: lat[min(len(lat) - 1, int(len(lat) * p))] * 1000
print(f"requests={len(lat)} duration={dur:.1f}s throughput={len(lat)/dur:.0f} req/s status={codes}")
print(f"latency ms: mean={statistics.mean(lat)*1000:.2f} p50={pct(.5):.2f} p95={pct(.95):.2f} p99={pct(.99):.2f}")
print("(each request = JWT verify + session/account lookup + cached policy + audit insert + proxy hop)")
