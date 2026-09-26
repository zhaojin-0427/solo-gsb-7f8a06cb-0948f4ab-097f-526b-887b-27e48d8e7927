#!/usr/bin/env python3
"""Sign a sample webhook request and POST it to the local verifier.

Usage (server must be running, e.g. via `docker compose up --build`):

    WEBHOOK_SECRET=dev-only-secret-change-me python3 scripts/example_client.py

Run it twice with the same nonce to see the replay protection respond
with 409 replayed_nonce (the script uses a fresh random nonce per run,
so force a replay with --nonce fixed-value).
"""

import hashlib
import hmac
import json
import os
import sys
import time
import urllib.error
import urllib.request
import uuid

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.signing import build_canonical_string

BASE_URL = os.environ.get("VERIFIER_URL", "http://localhost:8000")
SECRET = os.environ.get("WEBHOOK_SECRET", "dev-only-secret-change-me")


def main() -> None:
    nonce = (
        sys.argv[sys.argv.index("--nonce") + 1]
        if "--nonce" in sys.argv
        else uuid.uuid4().hex
    )
    payload = {
        "method": "post",  # lowercase on purpose: the server uppercases it
        "path": "/webhook",
        "query": [
            {"key": "source", "value": "github"},
            {"key": "tag", "value": "v1.0"},
            {"key": "tag", "value": "release"},  # repeated key
        ],
        "body": json.dumps({"event": "ping"}, separators=(",", ":")),
        "timestamp": int(time.time()),
        "nonce": nonce,
    }
    canonical = build_canonical_string(
        method=payload["method"].upper(),
        path=payload["path"],
        query_items=[(q["key"], q["value"]) for q in payload["query"]],
        body=payload["body"],
        timestamp=payload["timestamp"],
        nonce=payload["nonce"],
    )
    payload["signature"] = hmac.new(
        SECRET.encode("utf-8"), canonical.encode("utf-8"), hashlib.sha256
    ).hexdigest()

    print("Canonical string that was signed:")
    print(canonical)
    print()

    request = urllib.request.Request(
        f"{BASE_URL}/verify",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request) as resp:
            print(resp.status, resp.read().decode())
    except urllib.error.HTTPError as exc:
        print(exc.code, exc.read().decode())


if __name__ == "__main__":
    main()
