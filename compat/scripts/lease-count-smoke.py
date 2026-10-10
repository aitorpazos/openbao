# Copyright (c) OpenBao Contributors
# SPDX-License-Identifier: MPL-2.0
"""Live curl smoke test; requires an isolated dev server on port 8200."""
import json
import subprocess

BASE = "http://127.0.0.1:8200/v1/"

def call(method, path, body=None):
    args = ["curl", "-sS", "-w", "\n%{http_code}", "-X", method,
            "-H", "X-Vault-Token: compat-harness", BASE + path]
    if body is not None:
        args += ["-H", "Content-Type: application/json", "-d", json.dumps(body)]
    raw, status = subprocess.check_output(args, text=True).rsplit("\n", 1)
    return int(status), json.loads(raw) if raw else None

quota = "sys/quotas/lease-count/compat-smoke"
created = []
try:
    status, data = call("POST", quota, {"path": "auth/token/create", "max_leases": 1})
    assert status == 204, (status, data)
    print("configure max_leases=1: 204")
    payload = {"policies": ["default"], "ttl": "10m"}
    status, data = call("POST", "auth/token/create", payload)
    assert status == 200 and isinstance(data, dict), (status, data)
    created.append(data["auth"]["client_token"])
    print("first issuance: 200")
    status, data = call("POST", "auth/token/create", payload)
    assert status == 429 and "lease count quota exceeded" in str(data), (status, data)
    print("second issuance:", status, data)
    status, data = call("POST", "auth/token/revoke", {"token": created.pop()})
    assert status == 204, (status, data)
    print("revoke: 204")
    status, data = call("POST", "auth/token/create", payload)
    assert status == 200 and isinstance(data, dict), (status, data)
    created.append(data["auth"]["client_token"])
    print("issuance after revocation: 200")
finally:
    call("DELETE", quota)
    for token in created:
        call("POST", "auth/token/revoke", {"token": token})
