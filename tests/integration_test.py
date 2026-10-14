#!/usr/bin/env python3
"""End-to-end security tests. Needs a running gateway + demo service + PostgreSQL.

  JWT_SECRET=...  ADMIN_EMAIL=admin@example.com  ADMIN_PASSWORD=...  python3 tests/integration_test.py -v

(The same values the gateway was started with. JWT_SECRET is used ONLY to forge hostile tokens.)
"""
import base64
import hashlib
import hmac
import json
import os
import sys
import threading
import time
import unittest
import urllib.error
import urllib.request
import uuid

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tools"))
from device_agent import build_report  # noqa: E402

BASE = os.environ.get("GATEWAY_URL", "http://127.0.0.1:8080")
JWT_SECRET = os.environ["JWT_SECRET"]
ADMIN_EMAIL = os.environ.get("ADMIN_EMAIL", "admin@example.com")
ADMIN_PASSWORD = os.environ["ADMIN_PASSWORD"]
DEMO_UPSTREAM = os.environ.get("DEMO_UPSTREAM", "http://127.0.0.1:9000")
PW = "a-very-long-test-password-1"


def call(method, path, body=None, token=None, headers=None, retry=True):
    for _ in range(30):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(BASE + path, method=method, data=data)
        req.add_header("Content-Type", "application/json")
        if token:
            req.add_header("Authorization", "Bearer " + token)
        for k, v in (headers or {}).items():
            req.add_header(k, v)
        try:
            with urllib.request.urlopen(req, timeout=20) as r:
                status, raw = r.status, r.read()
        except urllib.error.HTTPError as e:
            status, raw = e.code, e.read()
        try:
            out = json.loads(raw)
        except Exception:
            out = raw.decode(errors="replace")
        if retry and status == 429 and isinstance(out, dict) and out.get("error") == "rate_limited":
            time.sleep(0.7)
            continue
        return status, out
    raise RuntimeError("still rate limited")


def b64(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def make_jwt(claims, secret=JWT_SECRET, alg="HS256", sign=True):
    h = b64(json.dumps({"alg": alg, "typ": "JWT"}).encode())
    p = b64(json.dumps(claims).encode())
    sig = b64(hmac.new(secret.encode(), f"{h}.{p}".encode(), hashlib.sha256).digest()) if sign else ""
    return f"{h}.{p}.{sig}"


def jwt_claims(token):
    p = token.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4)))


def login(email, pw=PW):
    s, d = call("POST", "/auth/login", {"email": email, "password": pw})
    assert s == 200, (s, d)
    return d["access_token"]


def new_user(admin, role=None):
    email = f"user-{uuid.uuid4().hex[:10]}@example.com"
    s, d = call("POST", "/auth/register", {"email": email, "password": PW})
    assert s == 201, (s, d)
    if role:
        s2, _ = call("POST", f"/admin/users/{d['id']}/role", {"role": role}, admin)
        assert s2 == 200
    return email, d["id"], login(email)


class ZeroTrust(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.admin = login(ADMIN_EMAIL, ADMIN_PASSWORD)
        cls.emp_email, cls.emp_id, cls.emp = new_user(cls.admin)
        cls.con_email, cls.con_id, cls.con = new_user(cls.admin, "contractor")
        s, d = call("GET", "/resources", token=cls.admin)
        cls.res = {r["name"]: r["id"] for r in d["resources"]}
        cls.dev = cls.enroll(cls.emp_id)

    @classmethod
    def enroll(cls, uid):
        s, d = call("POST", "/admin/devices", {"user_id": uid}, cls.admin)
        assert s == 201, (s, d)
        return d

    def attest(self, dev, token, **kw):
        return call("POST", "/device/attest", build_report(dev["device_id"], dev["secret"], **kw), token)

    def audit_reasons(self, email, reason):
        s, d = call("GET", f"/audit-logs?email={email}&reason={reason}&limit=50", token=self.admin)
        self.assertEqual(s, 200)
        return d["logs"]

    def audit_any(self, reason):
        s, d = call("GET", f"/audit-logs?reason={reason}&limit=5", token=self.admin)
        self.assertEqual(s, 200)
        return d["logs"]

    # ---------------------------------------------------------------- authentication
    def test_01_no_token_rejected(self):
        self.assertEqual(call("GET", "/resources")[0], 401)
        self.assertEqual(call("GET", f"/resources/{self.res['public-wiki']}")[0], 401)

    def test_02_resource_list_depends_on_role(self):
        names = {r["name"] for r in call("GET", "/resources", token=self.emp)[1]["resources"]}
        self.assertTrue({"hr-portal", "public-wiki"} <= names)
        self.assertNotIn("finance-reports", names)
        names = {r["name"] for r in call("GET", "/resources", token=self.con)[1]["resources"]}
        self.assertIn("public-wiki", names)
        self.assertFalse({"hr-portal", "finance-reports"} & names)

    def test_03_register_cannot_choose_role(self):
        email = f"sneaky-{uuid.uuid4().hex[:8]}@example.com"
        s, d = call("POST", "/auth/register", {"email": email, "password": PW, "role": "admin"})
        self.assertEqual((s, d["role"]), (201, "employee"))

    def test_04_input_validation_and_sql_injection(self):
        self.assertEqual(call("POST", "/auth/register", {"email": "nope", "password": PW})[0], 400)
        self.assertEqual(call("POST", "/auth/register", {"email": "a@b.co", "password": "short"})[0], 400)
        self.assertEqual(call("POST", "/auth/login", {"email": "' OR 1=1 --", "password": "x"})[0], 401)
        self.assertEqual(call("POST", "/auth/login", {"email": 5, "password": "x"})[0], 400)
        s, _ = call("POST", "/auth/login")  # no body
        self.assertEqual(s, 400)
        self.assertEqual(call("GET", "/resources/1%20OR%201=1", token=self.emp)[0], 400)
        s, d = call("GET", "/audit-logs?email=x'%20OR%20'1'='1", token=self.admin)
        self.assertEqual((s, d["logs"]), (200, []))
        self.assertEqual(call("GET", "/audit-logs?decision=bogus", token=self.admin)[0], 400)

    # ---------------------------------------------------------------- policy enforcement
    def test_10_public_resource_needs_no_device(self):
        s, d = call("GET", f"/resources/{self.res['public-wiki']}", token=self.emp)
        self.assertEqual(s, 200)
        self.assertEqual(d["app"], "public-wiki")
        self.assertEqual(d["served_to"], self.emp_email)  # identity propagated to the upstream

    def test_11_device_required_and_missing(self):
        s, _ = call("GET", f"/resources/{self.res['hr-portal']}", token=self.emp)
        self.assertEqual(s, 403)
        self.assertTrue(self.audit_reasons(self.emp_email, "device_missing"))

    def test_12_healthy_device_grants_access(self):
        s, d = self.attest(self.dev, self.emp)
        self.assertEqual((s, d["healthy"]), (200, True))
        s, d = call("GET", f"/resources/{self.res['hr-portal']}", token=self.emp,
                    headers={"X-Device-Id": self.dev["device_id"]})
        self.assertEqual((s, d["app"]), (200, "hr-portal"))

    def test_13_unhealthy_device_denied(self):
        dev2 = self.enroll(self.emp_id)
        s, d = self.attest(dev2, self.emp, disk_encrypted=False)
        self.assertEqual((s, d["healthy"]), (200, False))
        s, _ = call("GET", f"/resources/{self.res['hr-portal']}", token=self.emp,
                    headers={"X-Device-Id": dev2["device_id"]})
        self.assertEqual(s, 403)
        self.assertTrue(self.audit_reasons(self.emp_email, "device_unhealthy"))

    def test_14_forged_and_replayed_posture_rejected(self):
        dev3 = self.enroll(self.emp_id)
        # unhealthy device tries to claim "healthy" using an edited report
        rep = build_report(dev3["device_id"], dev3["secret"], disk_encrypted=False)
        rep["posture"]["disk_encrypted"] = True
        self.assertEqual(call("POST", "/device/attest", rep, self.emp)[0], 403)
        # attacker signs with a key they invented
        fake = build_report(dev3["device_id"], "0" * 64)
        self.assertEqual(call("POST", "/device/attest", fake, self.emp)[0], 403)
        self.assertTrue(self.audit_reasons(self.emp_email, "bad_signature"))
        # genuine report accepted once, replay rejected
        good = build_report(dev3["device_id"], dev3["secret"])
        self.assertEqual(call("POST", "/device/attest", good, self.emp)[0], 200)
        self.assertEqual(call("POST", "/device/attest", good, self.emp)[0], 409)
        # old timestamp rejected
        old = build_report(dev3["device_id"], dev3["secret"], ts=int(time.time()) - 3600)
        self.assertEqual(call("POST", "/device/attest", old, self.emp)[0], 400)
        # another user cannot submit posture for my device
        self.assertEqual(call("POST", "/device/attest",
                              build_report(dev3["device_id"], dev3["secret"]), self.con)[0], 403)

    def test_15_authenticated_but_wrong_role_denied(self):
        # even a perfectly healthy device cannot rescue a role the policy does not permit
        s, _ = call("GET", f"/resources/{self.res['finance-reports']}", token=self.emp,
                    headers={"X-Device-Id": self.dev["device_id"]})
        self.assertEqual(s, 403)
        self.assertTrue(self.audit_reasons(self.emp_email, "role_not_permitted"))
        s, d = call("GET", f"/resources/{self.res['finance-reports']}", token=self.admin,
                    headers={"X-Device-Id": "dev-doesnotexist"})
        self.assertEqual(s, 403)  # admin role is fine but admin has no enrolled device

    def test_16_policy_change_takes_effect_immediately(self):
        hr = self.res["hr-portal"]
        hdr = {"X-Device-Id": self.dev["device_id"]}
        call("GET", f"/resources/{hr}", token=self.con, headers=hdr)  # warms the policy cache
        self.assertTrue(self.audit_reasons(self.con_email, "role_not_permitted"))
        s, _ = call("POST", "/policies", {"resource_id": hr, "allowed_roles": ["employee", "admin", "contractor"]}, self.admin)
        self.assertEqual(s, 200)
        try:
            # contractor now passes the ROLE check at once (cache invalidated, not waiting for TTL)
            # but is stopped by the next control: stolen device id belongs to someone else.
            s, _ = call("GET", f"/resources/{hr}", token=self.con, headers=hdr)
            self.assertEqual(s, 403)
            self.assertTrue(self.audit_reasons(self.con_email, "device_not_owned"))
        finally:
            call("POST", "/policies", {"resource_id": hr, "allowed_roles": ["employee", "admin"]}, self.admin)
        s, _ = call("GET", f"/resources/{hr}", token=self.emp, headers=hdr)
        self.assertEqual(s, 200)

    def test_17_default_deny_without_policy_or_inactive(self):
        name = "tmp-" + uuid.uuid4().hex[:8]
        s, d = call("POST", "/resources", {"name": name, "upstream_url": DEMO_UPSTREAM + "/wiki"}, self.admin)
        self.assertEqual(s, 201)
        rid = d["id"]
        self.assertEqual(call("GET", f"/resources/{rid}", token=self.admin)[0], 403)  # no policy => deny
        self.assertTrue(self.audit_reasons(ADMIN_EMAIL, "no_policy"))
        call("POST", "/policies", {"resource_id": rid, "allowed_roles": ["admin"], "require_healthy_device": False}, self.admin)
        self.assertEqual(call("GET", f"/resources/{rid}", token=self.admin)[0], 200)
        call("POST", "/policies", {"resource_id": rid, "allowed_roles": ["admin"], "require_healthy_device": False, "active": False}, self.admin)
        self.assertEqual(call("GET", f"/resources/{rid}", token=self.admin)[0], 403)
        self.assertEqual(call("GET", "/resources/999999", token=self.admin)[0], 403)  # unknown == forbidden

    def test_18_admin_endpoints_require_admin(self):
        for m, p, b in [("GET", "/audit-logs", None), ("GET", "/metrics", None),
                        ("POST", "/policies", {"resource_id": 1, "allowed_roles": ["employee"]}),
                        ("POST", "/admin/devices", {"user_id": self.emp_id}),
                        ("POST", f"/admin/users/{self.emp_id}/role", {"role": "admin"})]:
            self.assertEqual(call(m, p, b, self.emp)[0], 403, p)
        s, d = call("GET", "/audit-logs?limit=5", token=self.admin)
        self.assertEqual(s, 200)
        self.assertTrue(d["logs"])

    # ---------------------------------------------------------------- token / session attacks
    def test_20_expired_token_rejected(self):
        c = jwt_claims(self.emp)
        c["exp"] = int(time.time()) - 5
        s, _ = call("GET", "/resources", token=make_jwt(c))
        self.assertEqual(s, 401)
        self.assertTrue(self.audit_any("token_expired"))

    def test_21_forged_tokens_rejected(self):
        good = jwt_claims(self.emp)
        admin_claims = dict(good, sub="1", role="admin")
        attacks = {
            "wrong secret": make_jwt(good, secret="x" * 40),
            "alg none": make_jwt(good, alg="none", sign=False),
            "tampered payload": self.emp.split(".")[0] + "." + b64(json.dumps(admin_claims).encode()) + "." + self.emp.split(".")[2],
            "garbage": "not.a.jwt",
            "unknown session": make_jwt(dict(good, jti="0" * 32)),
        }
        for name, tok in attacks.items():
            self.assertEqual(call("GET", "/resources", token=tok)[0], 401, name)

    def test_22_role_in_token_is_not_trusted(self):
        # A validly-signed token that LIES about the role (e.g. a bug elsewhere) must not elevate:
        # the gateway takes the role from the database, not from the token.
        c = jwt_claims(self.emp)
        c["role"] = "admin"
        s, _ = call("GET", "/audit-logs", token=make_jwt(c))
        self.assertEqual(s, 403)

    def test_23_logout_revokes_session(self):
        _, _, tok = new_user(self.admin)
        self.assertEqual(call("GET", "/resources", token=tok)[0], 200)
        self.assertEqual(call("POST", "/auth/logout", token=tok)[0], 200)
        self.assertEqual(call("GET", "/resources", token=tok)[0], 401)

    def test_24_disabled_account_blocked_immediately(self):
        email, uid, tok = new_user(self.admin)
        self.assertEqual(call("GET", "/resources", token=tok)[0], 200)
        self.assertEqual(call("POST", f"/admin/users/{uid}/disable", token=self.admin)[0], 200)
        self.assertEqual(call("GET", "/resources", token=tok)[0], 401)
        self.assertEqual(call("POST", "/auth/login", {"email": email, "password": PW})[0], 401)
        self.assertEqual(call("POST", f"/admin/users/{uid}/enable", token=self.admin)[0], 200)
        self.assertEqual(call("POST", "/auth/login", {"email": email, "password": PW})[0], 200)
        # re-enabling does NOT resurrect the old token: its session stays revoked
        self.assertEqual(call("GET", "/resources", token=tok)[0], 401)

    def test_25_role_change_applies_to_live_token(self):
        email, uid, tok = new_user(self.admin)
        self.assertEqual(call("GET", "/audit-logs?limit=1", token=tok)[0], 403)
        call("POST", f"/admin/users/{uid}/role", {"role": "admin"}, self.admin)
        self.assertEqual(call("GET", "/audit-logs?limit=1", token=tok)[0], 200)
        call("POST", f"/admin/users/{uid}/role", {"role": "employee"}, self.admin)
        self.assertEqual(call("GET", "/audit-logs?limit=1", token=tok)[0], 403)

    def test_26_login_throttling(self):
        email, _, _ = new_user(self.admin)
        codes = [call("POST", "/auth/login", {"email": email, "password": "wrong-password"})[0] for _ in range(5)]
        self.assertEqual(codes, [401] * 5)
        s, d = call("POST", "/auth/login", {"email": email, "password": "wrong-password"})
        self.assertEqual((s, d["error"]), (429, "login_locked"))
        s, d = call("POST", "/auth/login", {"email": email, "password": PW})  # even the right one
        self.assertEqual((s, d["error"]), (429, "login_locked"))

    # ---------------------------------------------------------------- failure scenarios
    def _tmp_resource(self, url):
        name = "tmp-" + uuid.uuid4().hex[:8]
        s, d = call("POST", "/resources", {"name": name, "upstream_url": url}, self.admin)
        self.assertEqual(s, 201, d)
        call("POST", "/policies", {"resource_id": d["id"], "allowed_roles": ["employee", "admin"], "require_healthy_device": False}, self.admin)
        return d["id"]

    def test_30_upstream_down_fails_safely(self):
        rid = self._tmp_resource("http://127.0.0.1:9/nothing")
        s, d = call("GET", f"/resources/{rid}", token=self.emp)
        self.assertEqual((s, d), (502, {"error": "bad_gateway"}))  # no internals leaked

    def test_31_upstream_timeout_is_bounded(self):
        rid = self._tmp_resource(DEMO_UPSTREAM + "/slow?sec=15")
        t0 = time.time()
        s, _ = call("GET", f"/resources/{rid}", token=self.emp)
        self.assertEqual(s, 502)
        self.assertLess(time.time() - t0, 9)

    def test_32_revoked_while_request_in_flight(self):
        rid = self._tmp_resource(DEMO_UPSTREAM + "/slow?sec=2")
        _, uid, tok = new_user(self.admin)
        out = {}
        t = threading.Thread(target=lambda: out.update(r=call("GET", f"/resources/{rid}", token=tok)))
        t.start()
        time.sleep(0.7)  # request is now waiting on the slow upstream
        call("POST", f"/admin/users/{uid}/revoke-sessions", token=self.admin)
        t.join()
        self.assertEqual(out["r"][0], 401)  # response withheld
        self.assertTrue(self.audit_any("revoked_during_request"))

    def test_33_concurrent_revocation_invariant(self):
        time.sleep(3)  # let the per-IP bucket refill
        wiki = self.res["public-wiki"]
        _, uid, tok = new_user(self.admin)
        revoked_at = [None]
        log, lock, stop = [], threading.Lock(), threading.Event()

        def worker():
            while not stop.is_set():
                t0 = time.monotonic()
                s, _ = call("GET", f"/resources/{wiki}", token=tok, retry=False)
                with lock:
                    log.append((t0, s))

        ths = [threading.Thread(target=worker) for _ in range(8)]
        [t.start() for t in ths]
        time.sleep(0.8)
        call("POST", f"/admin/users/{uid}/revoke-sessions", token=self.admin)
        revoked_at[0] = time.monotonic()
        time.sleep(0.8)
        stop.set()
        [t.join() for t in ths]
        before = [s for t0, s in log if t0 < revoked_at[0]]
        after = [s for t0, s in log if t0 > revoked_at[0]]
        self.assertIn(200, before, "requests should succeed before revocation")
        self.assertNotIn(200, after, "NO request that started after revocation may succeed")
        self.assertTrue(after, "test must have issued requests after revocation")

    def test_34_rate_limiting(self):
        time.sleep(3)
        codes, lock = [], threading.Lock()

        def worker():
            for _ in range(15):
                s, _ = call("GET", "/resources", retry=False)
                with lock:
                    codes.append(s)

        ths = [threading.Thread(target=worker) for _ in range(30)]
        [t.start() for t in ths]
        [t.join() for t in ths]
        self.assertIn(429, codes)
        time.sleep(3)
        s, text = call("GET", "/metrics", token=self.admin)
        self.assertEqual(s, 200)
        self.assertIn("zt_rate_limited_total", text)
        self.assertIn("zt_events_total", text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
