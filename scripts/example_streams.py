#!/usr/bin/env python3
"""Demonstrate out-of-order buffering and gap filling on /streams/events.

Usage (server must be running, e.g. via `docker compose up --build`):

    WEBHOOK_SECRET=dev-only-secret-change-me python3 scripts/example_streams.py

The script submits sequence 3, then 2, then 1 into a fresh stream: the
first two answers report an empty ``opened`` list (buffered behind a
gap), and the last one opens 1, 2 and 3 in a single watermark jump. A
duplicate-sequence submission and a replay are then demonstrated.
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
STREAM_ID = os.environ.get("STREAM_ID", f"demo-{uuid.uuid4().hex[:8]}")


def send_event(sequence, data, *, nonce=None, stream_id=STREAM_ID, body_override=None):
    body = body_override or json.dumps(
        {"stream_id": stream_id, "sequence": sequence, "data": data},
        separators=(",", ":"),
    )
    envelope = {
        "method": "POST",
        "path": "/streams/events",
        "query": [],
        "body": body,
        "timestamp": int(time.time()),
        "nonce": nonce or uuid.uuid4().hex,
    }
    canonical = build_canonical_string(
        envelope["method"],
        envelope["path"],
        [],
        envelope["body"],
        envelope["timestamp"],
        envelope["nonce"],
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
    try:
        with urllib.request.urlopen(request) as resp:
            return resp.status, json.loads(resp.read().decode())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode())


def show_ready(after_seq=0):
    url = f"{BASE_URL}/streams/{STREAM_ID}/ready?after_seq={after_seq}"
    with urllib.request.urlopen(url) as resp:
        payload = json.loads(resp.read().decode())
    print(f"GET ready?after_seq={after_seq} ->", json.dumps(payload, ensure_ascii=False))


def main() -> None:
    print(f"stream: {STREAM_ID}\n")

    for sequence, data in [(3, {"event": "shipped"}), (2, {"event": "paid"})]:
        status, payload = send_event(sequence, data)
        print(f"POST seq={sequence} -> {status}", payload)
    show_ready()  # still empty: gap at 1

    status, payload = send_event(1, {"event": "created"})
    print(f"POST seq={1} -> {status}", payload, "  # gap filled, 1,2,3 open")
    show_ready()
    show_ready(after_seq=2)  # incremental read

    # Duplicate sequence: 409, and the nonce stays usable.
    nonce = uuid.uuid4().hex
    status, payload = send_event(2, {"event": "paid-again"}, nonce=nonce)
    print(f"POST seq=2 again (nonce {nonce[:8]}…) -> {status}", payload.get("detail"))
    status, payload = send_event(4, {"event": "closed"}, nonce=nonce)
    print(f"POST seq=4 reusing that nonce -> {status}", payload)
    show_ready()


if __name__ == "__main__":
    main()
