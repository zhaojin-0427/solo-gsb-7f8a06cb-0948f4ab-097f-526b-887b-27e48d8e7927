"""End-to-end tests for POST /verify using FastAPI's TestClient."""

import hashlib
import hmac
import time
import uuid

import pytest
from fastapi.testclient import TestClient

from app.main import MAX_TIME_SKEW_SECONDS, app
from app.signing import build_canonical_string

SECRET = "test-secret"


def _sign(payload: dict, secret: str = SECRET) -> str:
    canonical = build_canonical_string(
        method=payload["method"].upper(),
        path=payload["path"],
        query_items=[(q["key"], q["value"]) for q in payload.get("query", [])],
        body=payload.get("body", ""),
        timestamp=payload["timestamp"],
        nonce=payload["nonce"],
    )
    return hmac.new(secret.encode(), canonical.encode(), hashlib.sha256).hexdigest()


def _payload(**overrides) -> dict:
    payload = {
        "method": "post",  # deliberately lowercase; server must uppercase
        "path": "/webhook",
        "query": [
            {"key": "b", "value": "2"},
            {"key": "a", "value": "1"},
            {"key": "a", "value": "0"},
            {"key": "sp ace", "value": "a&b"},
        ],
        "body": '{"event":"ping"}',
        "timestamp": int(time.time()),
        "nonce": uuid.uuid4().hex,
    }
    payload.update(overrides)
    payload.setdefault("signature", _sign(payload))
    return payload


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("WEBHOOK_SECRET", SECRET)
    monkeypatch.setenv("NONCE_DB_PATH", str(tmp_path / "nonces.db"))
    with TestClient(app) as c:
        yield c


def test_health(client):
    assert client.get("/health").json() == {"status": "ok"}


def test_valid_request_is_verified_and_method_is_uppercased(client):
    resp = client.post("/verify", json=_payload())
    assert resp.status_code == 200, resp.text
    assert resp.json()["ok"] is True
    assert resp.json()["reason"] == "verified"


def test_replayed_nonce_is_rejected_but_first_request_passes(client):
    payload = _payload()
    assert client.post("/verify", json=payload).status_code == 200

    resp = client.post("/verify", json=payload)
    assert resp.status_code == 409
    assert resp.json()["detail"]["error"] == "replayed_nonce"


def test_bad_signature_does_not_consume_nonce(client):
    payload = _payload(
        signature=hmac.new(b"other-secret", b"canonical", hashlib.sha256).hexdigest()
    )
    resp = client.post("/verify", json=payload)
    assert resp.status_code == 401
    assert resp.json()["detail"]["error"] == "invalid_signature"

    # The same nonce with the correct signature now succeeds: a failed
    # attempt did not consume it.
    payload["signature"] = _sign(payload)
    resp = client.post("/verify", json=payload)
    assert resp.status_code == 200


def test_malformed_signature_is_invalid_signature(client):
    resp = client.post("/verify", json=_payload(signature="ZZ" * 32))
    assert resp.status_code == 401
    assert resp.json()["detail"]["error"] == "invalid_signature"


def test_timestamp_out_of_window_in_the_past(client):
    payload = _payload(timestamp=int(time.time()) - MAX_TIME_SKEW_SECONDS - 1)
    resp = client.post("/verify", json=payload)
    assert resp.status_code == 401
    assert resp.json()["detail"]["error"] == "timestamp_out_of_window"


def test_timestamp_out_of_window_in_the_future(client):
    payload = _payload(timestamp=int(time.time()) + MAX_TIME_SKEW_SECONDS + 1)
    resp = client.post("/verify", json=payload)
    assert resp.status_code == 401
    assert resp.json()["detail"]["error"] == "timestamp_out_of_window"


def test_timestamp_just_inside_window_is_accepted(client):
    # One second inside the edge of the window must still pass the time
    # check (using the exact boundary would be flaky across a second tick).
    payload = _payload(timestamp=int(time.time()) - MAX_TIME_SKEW_SECONDS + 1)
    resp = client.post("/verify", json=payload)
    assert resp.status_code == 200


def test_stale_timestamp_never_consumes_nonce(client):
    stale = _payload(timestamp=int(time.time()) - MAX_TIME_SKEW_SECONDS - 1)
    assert client.post("/verify", json=stale).status_code == 401

    # Same nonce, fresh timestamp, same signature basis: should verify.
    fresh = _payload(nonce=stale["nonce"], timestamp=int(time.time()))
    assert client.post("/verify", json=fresh).status_code == 200


def test_independently_built_canonical_string_verifies(client):
    """Cross-check the server's serialization with a hand-built string."""
    nonce = uuid.uuid4().hex
    timestamp = int(time.time())
    body = '{"event":"ping"}'
    body_hash = hashlib.sha256(body.encode()).hexdigest()
    # Encoded pairs sorted: a=0, a=1, b=2, sp%20ace=a%26b
    canonical = (
        "POST\n/webhook\n"
        "a=0&a=1&b=2&sp%20ace=a%26b\n"
        f"{body_hash}\n{timestamp}\n{nonce}"
    )
    signature = hmac.new(SECRET.encode(), canonical.encode(), hashlib.sha256).hexdigest()
    payload = {
        "method": "post",
        "path": "/webhook",
        "query": [
            {"key": "b", "value": "2"},
            {"key": "a", "value": "1"},
            {"key": "a", "value": "0"},
            {"key": "sp ace", "value": "a&b"},
        ],
        "body": body,
        "timestamp": timestamp,
        "nonce": nonce,
        "signature": signature,
    }
    resp = client.post("/verify", json=payload)
    assert resp.status_code == 200, resp.text


def test_missing_required_field_is_422(client):
    resp = client.post("/verify", json={"method": "POST"})
    assert resp.status_code == 422
