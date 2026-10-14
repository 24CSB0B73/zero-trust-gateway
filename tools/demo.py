#!/usr/bin/env python3
"""Narrated walkthrough of the gateway for a live demo / screen recording.

  ADMIN_EMAIL=admin@example.com ADMIN_PASSWORD=... python3 tools/demo.py
"""
import json
import os
import sys
import time
import urllib.error
import urllib.request
import uuid

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from device_agent import build_report  # noqa: E402

BASE = os.environ.get("GATEWAY_URL", "http://127.0.0.1:8080")
ADMIN_EMAIL = os.environ.get("ADMIN_EMAIL", "admin@example.com")
ADMIN_PASSWORD = os.environ["ADMIN_PASSWORD"]


def call(method, path, body=None, token=None, headers=None):
    req = urllib.request.Request(BASE + path, method=method, data=json.dumps(body).encode() if body is not None else None)
    req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", "Bearer " + token)
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


def step(title, status, body, expect):
    mark = "PASS" if status == expect else "!!!!"
    print(f"[{mark}] {title}\n        -> HTTP {status} {json.dumps(body)[:110]}")
    time.sleep(0.3)


print("== Zero Trust Gateway demo ==\n")
_, d = call("POST", "/auth/login", {"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD})
admin = d["access_token"]
_, rl = call("GET", "/resources", token=admin)
ids = {r["name"]: r["id"] for r in rl["resources"]}

email = f"alice-{uuid.uuid4().hex[:6]}@example.com"
s, u = call("POST", "/auth/register", {"email": email, "password": "correct-horse-battery"})
step(f"Register {email} (role is forced to 'employee')", s, u, 201)
_, d = call("POST", "/auth/login", {"email": email, "password": "correct-horse-battery"})
tok = d["access_token"]

s, b = call("GET", f"/resources/{ids['public-wiki']}")
step("No token -> never reaches the app", s, b, 401)
s, b = call("GET", f"/resources/{ids['public-wiki']}", token=tok)
step("Authenticated employee opens public-wiki (no device needed)", s, b, 200)
s, b = call("GET", f"/resources/{ids['hr-portal']}", token=tok)
step("Authenticated, but hr-portal needs a healthy device -> DENIED", s, b, 403)

_, dev = call("POST", "/admin/devices", {"user_id": u["id"]}, admin)
print(f"        (admin enrolled device {dev['device_id']})")
bad = build_report(dev["device_id"], dev["secret"], disk_encrypted=False)
s, b = call("POST", "/device/attest", bad, tok)
step("Device reports disk NOT encrypted (signed, honest)", s, b, 200)
s, b = call("GET", f"/resources/{ids['hr-portal']}", token=tok, headers={"X-Device-Id": dev["device_id"]})
step("hr-portal with unhealthy device -> DENIED", s, b, 403)
forged = build_report(dev["device_id"], dev["secret"], disk_encrypted=False)
forged["posture"]["disk_encrypted"] = True
s, b = call("POST", "/device/attest", forged, tok)
step("User edits the report to claim 'healthy' -> signature check FAILS", s, b, 403)
time.sleep(1.1)
s, b = call("POST", "/device/attest", build_report(dev["device_id"], dev["secret"]), tok)
step("Device fixed + genuinely healthy report", s, b, 200)
s, b = call("GET", f"/resources/{ids['hr-portal']}", token=tok, headers={"X-Device-Id": dev["device_id"]})
step("hr-portal with healthy device -> ALLOWED", s, b, 200)
s, b = call("GET", f"/resources/{ids['finance-reports']}", token=tok, headers={"X-Device-Id": dev["device_id"]})
step("finance-reports: perfect device but wrong role -> DENIED", s, b, 403)

call("POST", f"/admin/users/{u['id']}/revoke-sessions", token=admin)
s, b = call("GET", f"/resources/{ids['hr-portal']}", token=tok, headers={"X-Device-Id": dev["device_id"]})
step("Admin revokes the session; same token is dead immediately", s, b, 401)

print(f"\nAudit trail for {email} (admin view, newest first):")
_, logs = call("GET", f"/audit-logs?limit=14&email={email}", token=admin)
for l in logs["logs"]:
    print(f"  {l['decision']:5} {l['action']:16} {l['reason']:28} {l['email']}")
