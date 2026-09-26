#!/usr/bin/env python3
"""Demonstrate resumable ordered consumption via /streams/.../claim and /ack.

Usage (server must be running, e.g. via `docker compose up --build`):

    WEBHOOK_SECRET=dev-only-secret-change-me python3 scripts/example_claims.py

The quick run (default) submits two events, claims sequence 1, shows the
409 from a second claim while the 30-second lease is live, rejects a wrong
ack token, then acknowledges with the real token and moves on.

Pass ``--wait-expiry`` to additionally sleep past the 30-second lease and
show timeout redelivery: the same sequence is claimed again with a fresh
token, the old token is rejected with 409, and only the new token acks.
"""

import argparse
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
STREAM_ID = os.environ.get("STREAM_ID", f"claims-{uuid.uuid4().hex[:8]}")
LEASE_SECONDS = 30


def send_event(sequence, data):
    body = json.dumps(
        {"stream_id": STREAM_ID, "sequence": sequence, "data": data},
        separators=(",", ":"),
    )
    envelope = {
        "method": "POST",
        "path": "/streams/events",
        "query": [],
        "body": body,
        "timestamp": int(time.time()),
        "nonce": uuid.uuid4().hex,
    }
    canonical = build_canonical_string(
        envelope["method"], envelope["path"], [],
        envelope["body"], envelope["timestamp"], envelope["nonce"],
    )
    envelope["signature"] = hmac.new(
        SECRET.encode("utf-8"), canonical.encode("utf-8"), hashlib.sha256
    ).hexdigest()

    request = urllib.request.Request(
        f"{BASE_URL}/streams/events",
        data=json.dumps(envelope).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request) as resp:
        return json.loads(resp.read().decode())


def request_json(method, path, payload=None):
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    request = urllib.request.Request(
        f"{BASE_URL}{path}", data=data,
        headers={"Content-Type": "application/json"}, method=method,
    )
    try:
        with urllib.request.urlopen(request) as resp:
            raw = resp.read().decode()
            return resp.status, (json.loads(raw) if raw else None)
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode())


def claim():
    return request_json("POST", f"/streams/{STREAM_ID}/claim")


def ack(token):
    return request_json("POST", f"/streams/{STREAM_ID}/ack", {"token": token})


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--wait-expiry",
        action="store_true",
        help=f"sleep past the {LEASE_SECONDS}s lease to demonstrate redelivery",
    )
    args = parser.parse_args()

    print(f"stream: {STREAM_ID}\n")

    print("submit seq 1, 2 ->", send_event(1, {"event": "created"}))
    print("submit seq 2    ->", send_event(2, {"event": "paid"}))

    # 1) First claim gets the very next open sequence (never past the
    #    watermark) plus a random token and an expiry timestamp.
    status, first = claim()
    print(f"\nPOST claim #1 -> {status}", json.dumps(first, ensure_ascii=False))
    token = first["token"]

    # 2) While the lease is live, another claim conflicts with 409.
    status, body = claim()
    print(f"POST claim #2 while leased -> {status}", body.get("detail", body))

    # 3) An old/wrong token cannot acknowledge; the confirmed cursor stays.
    status, body = ack("a" * len(token))
    print("POST ack with wrong token ->", status, body.get("detail", body))

    # 4) The real token acknowledges seq 1 atomically and clears the lease.
    status, body = ack(token)
    print("POST ack with real token ->", status, body)

    # 5) A duplicate ack is rejected: the lease is already gone.
    status, body = ack(token)
    print("POST duplicate ack       ->", status, body.get("detail", body))

    # 6) Seq 2 is now the next claim; leave it leased for the expiry demo.
    status, leased = claim()
    print("\nPOST claim seq 2 ->", status, json.dumps(leased, ensure_ascii=False))

    if not args.wait_expiry:
        # Finish cleanly so the run itself stays quick.
        status, body = ack(leased["token"])
        print("POST ack seq 2 ->", status, body)
        print(
            "\n(re-run with --wait-expiry to see 30s lease timeout and "
            "redelivery with a rotated token)"
        )
        return

    print(f"\nsleeping {LEASE_SECONDS + 1}s until the lease expires ...")
    time.sleep(LEASE_SECONDS + 1)

    status, redelivered = claim()
    print("POST claim after expiry ->", status,
          json.dumps(redelivered, ensure_ascii=False))
    assert redelivered["sequence"] == leased["sequence"]
    assert redelivered["token"] != leased["token"]

    status, body = ack(leased["token"])
    print("POST ack with the EXPIRED old token ->", status,
          body.get("detail", body))

    status, body = ack(redelivered["token"])
    print("POST ack with the new token ->", status, body)

    status, _ = claim()
    print("POST claim on drained stream ->", status, "(204 No Content)")


if __name__ == "__main__":
    main()
