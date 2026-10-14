#!/usr/bin/env python3
"""Simulated trusted device agent.

A real agent (MDM / EDR) would read posture from the OS and keep `secret` in a TPM/keychain.
Here we simulate it: the agent signs the posture report with the per-device secret that the
admin got at enrollment time, so the gateway can verify the report was NOT edited in transit
or invented by the user.

    python3 tools/device_agent.py --gateway http://localhost:8080 --token $TOKEN \
        --device-id dev-xxxx --secret <secret>                 # healthy device
    ... --disk-unencrypted                                      # unhealthy device
"""
import argparse
import hashlib
import hmac
import json
import time
import urllib.error
import urllib.request


def build_report(device_id, secret, os_patched=True, disk_encrypted=True,
                 firewall_on=True, antivirus_on=True, ts=None):
    ts = int(time.time()) if ts is None else ts
    bits = "".join("1" if x else "0" for x in (os_patched, disk_encrypted, firewall_on, antivirus_on))
    canonical = f"{device_id}|{ts}|{bits}"
    sig = hmac.new(secret.encode(), canonical.encode(), hashlib.sha256).hexdigest()
    return {
        "device_id": device_id,
        "ts": ts,
        "posture": {"os_patched": os_patched, "disk_encrypted": disk_encrypted,
                    "firewall_on": firewall_on, "antivirus_on": antivirus_on},
        "signature": sig,
    }


def send(gateway, token, report):
    req = urllib.request.Request(gateway + "/device/attest", data=json.dumps(report).encode(),
                                 method="POST",
                                 headers={"Content-Type": "application/json",
                                          "Authorization": "Bearer " + token})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--gateway", default="http://localhost:8080")
    ap.add_argument("--token", required=True)
    ap.add_argument("--device-id", required=True)
    ap.add_argument("--secret", required=True)
    ap.add_argument("--os-unpatched", action="store_true")
    ap.add_argument("--disk-unencrypted", action="store_true")
    ap.add_argument("--firewall-off", action="store_true")
    ap.add_argument("--antivirus-off", action="store_true")
    ap.add_argument("--loop", type=int, default=0, help="re-send every N seconds (heartbeat)")
    a = ap.parse_args()
    while True:
        rep = build_report(a.device_id, a.secret, not a.os_unpatched, not a.disk_unencrypted,
                           not a.firewall_off, not a.antivirus_off)
        print(send(a.gateway, a.token, rep))
        if not a.loop:
            break
        time.sleep(a.loop)
