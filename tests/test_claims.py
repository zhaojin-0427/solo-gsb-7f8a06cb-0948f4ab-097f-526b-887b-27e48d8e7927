"""End-to-end tests for resumable, ordered claim/ack consumption."""

import hashlib
import hmac
import json
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.signing import build_canonical_string

SECRET = "test-secret"
LEASE_TTL = 30


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


def _event_payload(stream_id, sequence, data, *, nonce=None, timestamp=None):
    body = json.dumps(
        {"stream_id": stream_id, "sequence": sequence, "data": data},
        separators=(",", ":"),
    )
    payload = {
        "method": "POST",
        "path": "/streams/events",
        "query": [],
        "body": body,
        "timestamp": timestamp if timestamp is not None else int(time.time()),
        "nonce": nonce if nonce is not None else uuid.uuid4().hex,
    }
    payload["signature"] = _sign(payload)
    return payload


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("WEBHOOK_SECRET", SECRET)
    monkeypatch.setenv("NONCE_DB_PATH", str(tmp_path / "nonces.db"))
    with TestClient(app) as c:
        yield c


def _submit(client, stream_id, sequence, data):
    return client.post(
        "/streams/events",
        json=_event_payload(stream_id, sequence, data),
    )


def _claim(client, stream_id):
    return client.post(f"/streams/{stream_id}/claim")


def _ack(client, stream_id, token):
    return client.post(f"/streams/{stream_id}/ack", json={"token": token})


# --- basic claim / ack lifecycle --------------------------------------------


def test_claim_on_unknown_stream_is_204(client):
    resp = _claim(client, "nope")
    assert resp.status_code == 204
    assert resp.content == b""


def test_claim_returns_next_open_event_with_lease(client):
    now = int(time.time())
    assert _submit(client, "s1", 1, {"v": 1}).status_code == 200

    resp = _claim(client, "s1")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["stream_id"] == "s1"
    assert body["sequence"] == 1
    assert body["data"] == {"v": 1}
    assert isinstance(body["token"], str) and len(body["token"]) >= 32
    assert body["expires_at"] >= now + LEASE_TTL
    assert body["expires_at"] <= int(time.time()) + LEASE_TTL + 1


def test_second_claim_while_lease_live_is_409(client):
    _submit(client, "s1", 1, {"v": 1})
    assert _claim(client, "s1").status_code == 200

    resp = _claim(client, "s1")
    assert resp.status_code == 409
    assert resp.json()["detail"]["error"] == "lease_active"


def test_ack_advances_confirmed_sequence_and_clears_lease(client):
    _submit(client, "s1", 1, {"v": 1})
    token = _claim(client, "s1").json()["token"]

    resp = _ack(client, "s1", token)
    assert resp.status_code == 200, resp.text
    assert resp.json() == {
        "ok": True,
        "stream_id": "s1",
        "sequence": 1,
        "confirmed_seq": 1,
    }

    # Lease cleared and everything open was consumed: 204, not 409.
    assert _claim(client, "s1").status_code == 204


def test_consume_many_in_strict_order(client):
    for i in range(1, 4):
        assert _submit(client, "s1", i, {"v": i}).status_code == 200

    for i in range(1, 4):
        claim = _claim(client, "s1")
        assert claim.status_code == 200, claim.text
        assert claim.json()["sequence"] == i
        # The live lease blocks another claim until the ack lands.
        assert _claim(client, "s1").status_code == 409
        assert _ack(client, "s1", claim.json()["token"]).status_code == 200

    # Every open event is consumed; the cursor now meets the watermark.
    assert _claim(client, "s1").status_code == 204


def test_claim_never_crosses_watermark(client):
    # Only 3 exists: buffered behind a gap at 1, nothing is open.
    _submit(client, "s1", 3, {"v": 3})
    assert _claim(client, "s1").status_code == 204

    # Filling 1 opens 1..3 but the claim still hands out only seq 1.
    _submit(client, "s1", 1, {"v": 1})
    _submit(client, "s1", 2, {"v": 2})
    claim = _claim(client, "s1").json()
    assert claim["sequence"] == 1

    _ack(client, "s1", claim["token"])
    claim = _claim(client, "s1").json()
    assert claim["sequence"] == 2


def test_newly_opened_event_becomes_claimable_after_lease_cleared(client):
    _submit(client, "s1", 1, {"v": 1})
    claim = _claim(client, "s1")
    assert claim.json()["sequence"] == 1
    # Gap at 2: after acking 1 there is nothing open yet.
    assert _ack(client, "s1", claim.json()["token"]).status_code == 200
    assert _claim(client, "s1").status_code == 204

    _submit(client, "s1", 2, {"v": 2})
    assert _claim(client, "s1").json()["sequence"] == 2


# --- invalid / duplicate acknowledgements ------------------------------------


def test_ack_without_any_lease_is_409(client):
    _submit(client, "s1", 1, {"v": 1})
    resp = _ack(client, "s1", "never-issued")
    assert resp.status_code == 409
    assert resp.json()["detail"]["error"] == "no_active_lease"
    # Cursor did not move: the event is still claimable.
    assert _claim(client, "s1").json()["sequence"] == 1


def test_ack_with_wrong_token_is_409(client):
    _submit(client, "s1", 1, {"v": 1})
    _claim(client, "s1")
    resp = _ack(client, "s1", "deadbeef" * 8)
    assert resp.status_code == 409
    assert resp.json()["detail"]["error"] == "invalid_token"
    # Original lease still active.
    assert _claim(client, "s1").status_code == 409


def test_duplicate_ack_is_409_and_does_not_readvance(client):
    _submit(client, "s1", 1, {"v": 1})
    _submit(client, "s1", 2, {"v": 2})
    token = _claim(client, "s1").json()["token"]
    assert _ack(client, "s1", token).status_code == 200

    resp = _ack(client, "s1", token)
    assert resp.status_code == 409
    assert resp.json()["detail"]["error"] == "no_active_lease"
    # Confirmed cursor is still 1.
    assert _claim(client, "s1").json()["sequence"] == 2


def test_ack_requires_non_empty_token(client):
    assert _ack(client, "s1", "").status_code == 422
    assert client.post("/streams/s1/ack", json={}).status_code == 422


# --- lease expiry ------------------------------------------------------------


@pytest.fixture()
def frozen_clock(monkeypatch):
    """Freeze time.time (shared by app.main and app.db) at a controllable value."""
    current = {"t": 1_800_000_000}
    monkeypatch.setattr(time, "time", lambda: current["t"])
    return current


def test_expired_lease_can_be_reclaimed_with_a_new_token(client, frozen_clock):
    _submit(client, "s1", 1, {"v": 1})
    first = _claim(client, "s1")
    assert first.status_code == 200
    first_token = first.json()["token"]
    assert first.json()["expires_at"] == frozen_clock["t"] + LEASE_TTL

    # Still live one second before expiry.
    frozen_clock["t"] += LEASE_TTL - 1
    assert _claim(client, "s1").status_code == 409

    # After expiry: same sequence redelivered with a rotated token.
    frozen_clock["t"] += 2
    second = _claim(client, "s1")
    assert second.status_code == 200
    assert second.json()["sequence"] == 1
    assert second.json()["token"] != first_token
    assert second.json()["expires_at"] == frozen_clock["t"] + LEASE_TTL

    # The old token is now worthless; the new one confirms the event.
    stale = _ack(client, "s1", first_token)
    assert stale.status_code == 409
    assert stale.json()["detail"]["error"] == "invalid_token"

    ok = _ack(client, "s1", second.json()["token"])
    assert ok.status_code == 200
    assert ok.json()["confirmed_seq"] == 1
    assert _claim(client, "s1").status_code == 204


def test_ack_after_expiry_is_409_without_advancing(client, frozen_clock):
    _submit(client, "s1", 1, {"v": 1})
    token = _claim(client, "s1").json()["token"]

    frozen_clock["t"] += LEASE_TTL + 1
    resp = _ack(client, "s1", token)
    assert resp.status_code == 409
    assert resp.json()["detail"]["error"] == "lease_expired"

    # Cursor unchanged: the same sequence is still the one to claim.
    redelivery = _claim(client, "s1")
    assert redelivery.status_code == 200
    assert redelivery.json()["sequence"] == 1


# --- concurrency -------------------------------------------------------------


def test_concurrent_claims_serialise_to_one_lease(client):
    for i in range(1, 11):
        _submit(client, "s1", i, {"v": i})

    barrier = threading.Barrier(8)

    def claim_once(_):
        barrier.wait()
        return _claim(client, "s1")

    with ThreadPoolExecutor(max_workers=8) as pool:
        responses = list(pool.map(claim_once, range(8)))

    assert sorted(r.status_code for r in responses) == [200] + [409] * 7
    winners = [r for r in responses if r.status_code == 200]
    assert {r.json()["sequence"] for r in winners} == {1}
    assert {r.json()["detail"]["error"] for r in responses if r.status_code == 409} == {
        "lease_active"
    }


def test_concurrent_acks_serialise_to_one_success(client):
    _submit(client, "s1", 1, {"v": 1})
    token = _claim(client, "s1").json()["token"]

    barrier = threading.Barrier(8)

    def ack_once(_):
        barrier.wait()
        return _ack(client, "s1", token)

    with ThreadPoolExecutor(max_workers=8) as pool:
        responses = list(pool.map(ack_once, range(8)))

    assert sorted(r.status_code for r in responses) == [200] + [409] * 7
    # Exactly one confirmation, cursor at 1.
    assert _claim(client, "s1").status_code == 204


def test_sequential_claim_ack_drains_the_stream(client):
    for i in range(1, 21):
        _submit(client, "s1", i, {"v": i})

    for expected in range(1, 21):
        claim = _claim(client, "s1")
        assert claim.status_code == 200
        assert claim.json()["sequence"] == expected
        assert _ack(client, "s1", claim.json()["token"]).status_code == 200

    assert _claim(client, "s1").status_code == 204


# --- durability across restart -----------------------------------------------


def test_lease_and_confirmed_cursor_survive_restart(client, tmp_path, monkeypatch):
    _submit(client, "s1", 1, {"v": 1})
    _submit(client, "s1", 2, {"v": 2})
    token = _claim(client, "s1").json()["token"]

    # Simulate a process restart: lifespan builds a fresh NonceStore over
    # the same SQLite file.
    with TestClient(app) as restarted:
        # The unexpired lease is still held: a second claim conflicts.
        assert _claim(restarted, "s1").status_code == 409
        # And the same token still completes the ack after the restart.
        resp = _ack(restarted, "s1", token)
        assert resp.status_code == 200
        assert resp.json()["confirmed_seq"] == 1

    with TestClient(app) as restarted_again:
        # Confirmed cursor persisted: seq 2 is now the next claim.
        claim = _claim(restarted_again, "s1")
        assert claim.status_code == 200
        assert claim.json()["sequence"] == 2


# --- read-only endpoint stays independent ------------------------------------


def test_ready_still_readonly_alongside_leases(client):
    _submit(client, "s1", 1, {"v": 1})
    _claim(client, "s1")
    # Claiming does not hide anything from the non-destructive read.
    resp = client.get("/streams/s1/ready")
    assert resp.status_code == 200
    assert [e["sequence"] for e in resp.json()["events"]] == [1]
