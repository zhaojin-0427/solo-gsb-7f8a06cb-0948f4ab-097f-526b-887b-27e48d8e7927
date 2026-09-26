"""End-to-end tests for ordered stream ingestion and reads."""

import hashlib
import hmac
import json
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor

import pytest
from fastapi.testclient import TestClient

from app.main import MAX_TIME_SKEW_SECONDS, app
from app.signing import build_canonical_string

SECRET = "test-secret"
EVENTS_PATH = "/streams/events"


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


def _event_payload(
    stream_id: str,
    sequence: int,
    data,
    *,
    path: str = EVENTS_PATH,
    nonce: str | None = None,
    timestamp: int | None = None,
    **overrides,
) -> dict:
    body = json.dumps(
        {"stream_id": stream_id, "sequence": sequence, "data": data},
        separators=(",", ":"),
    )
    payload = {
        "method": "POST",
        "path": path,
        "query": [],
        "body": body,
        "timestamp": timestamp if timestamp is not None else int(time.time()),
        "nonce": nonce if nonce is not None else uuid.uuid4().hex,
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


def _submit(client, stream_id, sequence, data, **kw):
    return client.post(
        "/streams/events", json=_event_payload(stream_id, sequence, data, **kw)
    )


def _ready(client, stream_id, after_seq=0):
    return client.get(f"/streams/{stream_id}/ready", params={"after_seq": after_seq})


# --- basic in-order behaviour -----------------------------------------------


def test_first_events_open_in_order(client):
    r1 = _submit(client, "s1", 1, {"a": 1})
    assert r1.status_code == 200, r1.text
    body = r1.json()
    assert body["stream_id"] == "s1"
    assert body["sequence"] == 1
    assert body["watermark"] == 1
    assert body["opened"] == [1]

    r2 = _submit(client, "s1", 2, "x")
    assert r2.status_code == 200
    assert r2.json()["watermark"] == 2
    assert r2.json()["opened"] == [2]


def test_ready_returns_watermarked_events_in_sequence_order(client):
    _submit(client, "s1", 1, {"v": 1})
    _submit(client, "s1", 2, {"v": 2})
    resp = _ready(client, "s1")
    assert resp.status_code == 200
    assert resp.json() == {
        "stream_id": "s1",
        "watermark": 2,
        "events": [
            {"sequence": 1, "data": {"v": 1}},
            {"sequence": 2, "data": {"v": 2}},
        ],
    }


def test_ready_filters_by_after_seq(client):
    for i in range(1, 4):
        _submit(client, "s1", i, {"v": i})
    resp = _ready(client, "s1", after_seq=1)
    assert [e["sequence"] for e in resp.json()["events"]] == [2, 3]
    assert resp.json()["watermark"] == 3

    resp = _ready(client, "s1", after_seq=3)
    assert resp.json()["events"] == []


def test_read_is_non_destructive(client):
    _submit(client, "s1", 1, {"v": 1})
    assert _ready(client, "s1").json()["events"] == [
        {"sequence": 1, "data": {"v": 1}}
    ]
    # Reading again yields the same event.
    assert _ready(client, "s1").json()["events"] == [
        {"sequence": 1, "data": {"v": 1}}
    ]


def test_unknown_stream_is_empty(client):
    resp = _ready(client, "nope")
    assert resp.status_code == 200
    assert resp.json() == {"stream_id": "nope", "watermark": 0, "events": []}


def test_after_seq_must_be_non_negative(client):
    assert _ready(client, "s1", after_seq=-1).status_code == 422


# --- out-of-order buffering and gap filling ---------------------------------


def test_out_of_order_events_are_buffered_until_gap_filled(client):
    # 3 arrives before 1 and 2: buffered, nothing opens.
    r3 = _submit(client, "s1", 3, {"v": 3})
    assert r3.status_code == 200
    assert r3.json()["opened"] == []
    assert r3.json()["watermark"] == 0

    assert _ready(client, "s1").json()["events"] == []

    # 2 alone still leaves the gap at 1.
    r2 = _submit(client, "s1", 2, {"v": 2})
    assert r2.json()["opened"] == []
    assert r2.json()["watermark"] == 0
    assert _ready(client, "s1").json()["events"] == []

    # Filling 1 opens 1, 2 and 3 in one watermark jump.
    r1 = _submit(client, "s1", 1, {"v": 1})
    assert r1.json()["watermark"] == 3
    assert r1.json()["opened"] == [1, 2, 3]

    resp = _ready(client, "s1")
    assert resp.json()["watermark"] == 3
    assert [(e["sequence"], e["data"]) for e in resp.json()["events"]] == [
        (1, {"v": 1}),
        (2, {"v": 2}),
        (3, {"v": 3}),
    ]


def test_gap_fill_opens_only_the_contiguous_prefix(client):
    # Buffered 2, 3 and 5: filling 1 opens [1, 2, 3]; 5 waits for 4.
    _submit(client, "s1", 3, 3)
    _submit(client, "s1", 5, 5)
    _submit(client, "s1", 2, 2)
    r1 = _submit(client, "s1", 1, 1)
    assert r1.json()["opened"] == [1, 2, 3]
    assert r1.json()["watermark"] == 3

    r4 = _submit(client, "s1", 4, 4)
    assert r4.json()["opened"] == [4, 5]
    assert r4.json()["watermark"] == 5
    assert [e["sequence"] for e in _ready(client, "s1").json()["events"]] == [
        1, 2, 3, 4, 5
    ]


def test_streams_are_independent(client):
    _submit(client, "a", 2, None)  # buffered behind gap
    r = _submit(client, "b", 1, "first")
    assert r.json()["opened"] == [1]
    assert r.json()["watermark"] == 1
    assert _ready(client, "a").json()["events"] == []
    assert [e["sequence"] for e in _ready(client, "b").json()["events"]] == [1]


def test_arbitrary_data_shapes_round_trip(client):
    for sequence, data in enumerate(
        [None, True, 42, 3.5, "str", [1, 2], {"nested": {"x": [True, None]}}],
        start=1,
    ):
        assert _submit(client, "s1", sequence, data).status_code == 200
    events = _ready(client, "s1").json()["events"]
    assert [e["data"] for e in events] == [
        None, True, 42, 3.5, "str", [1, 2], {"nested": {"x": [True, None]}}
    ]


def test_non_ascii_data_round_trips(client):
    _submit(client, "s1", 1, {"msg": "你好，世界"})
    events = _ready(client, "s1").json()["events"]
    assert events == [{"sequence": 1, "data": {"msg": "你好，世界"}}]


# --- duplicates --------------------------------------------------------------


def test_duplicate_sequence_conflicts(client):
    assert _submit(client, "s1", 1, {"v": 1}).status_code == 200
    resp = _submit(client, "s1", 1, {"v": 9})
    assert resp.status_code == 409
    assert resp.json()["detail"]["error"] == "duplicate_sequence"


def test_duplicate_buffered_sequence_conflicts(client):
    # A duplicate conflicts even while the event is still buffered.
    assert _submit(client, "s1", 3, {"v": 3}).status_code == 200
    resp = _submit(client, "s1", 3, {"v": 33})
    assert resp.status_code == 409
    assert resp.json()["detail"]["error"] == "duplicate_sequence"


def test_duplicate_sequence_does_not_consume_nonce(client):
    _submit(client, "s1", 1, {"v": 1})
    nonce = uuid.uuid4().hex
    dup = _event_payload("s1", 1, {"v": 9}, nonce=nonce)
    assert client.post("/streams/events", json=dup).status_code == 409

    # Same nonce reused for a fresh, valid sequence: must still work.
    retry = _event_payload("s1", 2, {"v": 2}, nonce=nonce)
    resp = client.post("/streams/events", json=retry)
    assert resp.status_code == 200, resp.text
    assert resp.json()["opened"] == [2]


# --- signed body validation --------------------------------------------------


@pytest.mark.parametrize(
    "body",
    [
        "",
        "not json",
        "[]",
        '"a string"',
        "42",
        "null",
        "{}",
        json.dumps({"sequence": 1, "data": {}}),
        json.dumps({"stream_id": "", "sequence": 1, "data": {}}),
        json.dumps({"stream_id": 5, "sequence": 1, "data": {}}),
        json.dumps({"stream_id": "s1", "data": {}}),
        json.dumps({"stream_id": "s1", "sequence": 0, "data": {}}),
        json.dumps({"stream_id": "s1", "sequence": -1, "data": {}}),
        json.dumps({"stream_id": "s1", "sequence": 1.0, "data": {}}),
        json.dumps({"stream_id": "s1", "sequence": True, "data": {}}),
        json.dumps({"stream_id": "s1", "sequence": "1", "data": {}}),
        json.dumps({"stream_id": "s1", "sequence": 1}),
        json.dumps({"stream_id": "s1", "sequence": 2**64, "data": {}}),
    ],
)
def test_invalid_event_bodies_are_400(client, body):
    payload = _event_payload("ignored", 1, {}, body=body)
    resp = client.post("/streams/events", json=payload)
    assert resp.status_code == 400, body
    assert resp.json()["detail"]["error"] == "invalid_event_body"


def test_invalid_body_does_not_consume_nonce(client):
    nonce = uuid.uuid4().hex
    bad = _event_payload("s1", 1, {}, body="not json", nonce=nonce)
    assert client.post("/streams/events", json=bad).status_code == 400

    good = _event_payload("s1", 1, {"v": 1}, nonce=nonce)
    assert client.post("/streams/events", json=good).status_code == 200


# --- signing / nonce semantics -----------------------------------------------


def test_bad_signature_does_not_consume_nonce(client):
    nonce = uuid.uuid4().hex
    bad = _event_payload(
        "s1", 1, {}, nonce=nonce,
        signature="a" * 64,
    )
    resp = client.post("/streams/events", json=bad)
    assert resp.status_code == 401
    assert resp.json()["detail"]["error"] == "invalid_signature"

    good = _event_payload("s1", 1, {}, nonce=nonce)
    assert client.post("/streams/events", json=good).status_code == 200


def test_timestamp_outside_window_is_401_and_does_not_consume_nonce(client):
    nonce = uuid.uuid4().hex
    stale = _event_payload(
        "s1", 1, {},
        nonce=nonce,
        timestamp=int(time.time()) - MAX_TIME_SKEW_SECONDS - 1,
    )
    assert client.post("/streams/events", json=stale).status_code == 401

    fresh = _event_payload("s1", 1, {}, nonce=nonce)
    assert client.post("/streams/events", json=fresh).status_code == 200


def test_signature_covers_the_raw_body(client):
    payload = _event_payload("s1", 1, {"v": 1})
    # Tamper with the signed body string without updating the signature.
    payload["body"] = json.dumps(
        {"stream_id": "s1", "sequence": 1, "data": {"v": 2}},
        separators=(",", ":"),
    )
    resp = client.post("/streams/events", json=payload)
    assert resp.status_code == 401
    assert resp.json()["detail"]["error"] == "invalid_signature"


def test_nonce_is_global_across_verify_and_streams(client):
    nonce = uuid.uuid4().hex
    verify_payload = {
        "method": "POST",
        "path": "/webhook",
        "query": [],
        "body": "{}",
        "timestamp": int(time.time()),
        "nonce": nonce,
    }
    verify_payload["signature"] = _sign(verify_payload)
    assert client.post("/verify", json=verify_payload).status_code == 200

    event = _event_payload("s1", 1, {}, nonce=nonce)
    resp = client.post("/streams/events", json=event)
    assert resp.status_code == 409
    assert resp.json()["detail"]["error"] == "replayed_nonce"


def test_replayed_nonce_does_not_store_event(client):
    payload = _event_payload("s1", 1, {"v": 1})
    assert client.post("/streams/events", json=payload).status_code == 200
    assert client.post("/streams/events", json=payload).status_code == 409
    # Exactly one event present, readable once.
    assert len(_ready(client, "s1").json()["events"]) == 1


def test_missing_envelope_field_is_422(client):
    resp = client.post("/streams/events", json={"method": "POST"})
    assert resp.status_code == 422


# --- concurrency -------------------------------------------------------------


def test_concurrent_gap_filling_advances_watermark_exactly_once(client):
    # Buffer sequences 2..50 with a gap at 1; then submit 1 many times
    # concurrently with distinct nonces. Exactly one wins, the rest are
    # duplicate conflicts, and all of 1..50 open once.
    for i in range(2, 51):
        assert _submit(client, "s1", i, {"v": i}).status_code == 200

    barrier = threading.Barrier(4)

    def submit_one(idx):
        payload = _event_payload(
            "s1", 1, {"v": 1}, nonce=f"race-nonce-{idx}"
        )
        barrier.wait()
        return client.post("/streams/events", json=payload)

    with ThreadPoolExecutor(max_workers=4) as pool:
        responses = list(pool.map(submit_one, range(4)))

    statuses = sorted(r.status_code for r in responses)
    assert statuses == [200, 409, 409, 409]
    ok = next(r for r in responses if r.status_code == 200)
    assert ok.json()["opened"] == list(range(1, 51))
    assert ok.json()["watermark"] == 50

    # Losing nonces were rolled back and remain usable.
    losers = [r for r in responses if r.status_code == 409]
    assert {r.json()["detail"]["error"] for r in losers} == {"duplicate_sequence"}
    loser_index = responses.index(losers[0])

    retry = _event_payload(
        "s1", 51, {"v": 51}, nonce=f"race-nonce-{loser_index}"
    )
    assert client.post("/streams/events", json=retry).status_code == 200

    events = _ready(client, "s1").json()["events"]
    assert [e["sequence"] for e in events] == list(range(1, 52))


def test_concurrent_distinct_sequences_all_land(client):
    barrier = threading.Barrier(5)

    def submit_one(seq):
        payload = _event_payload("s2", seq, {"v": seq}, nonce=f"n-{seq}")
        barrier.wait()
        return client.post("/streams/events", json=payload)

    with ThreadPoolExecutor(max_workers=5) as pool:
        responses = list(pool.map(submit_one, [3, 1, 4, 2, 5]))

    assert all(r.status_code == 200 for r in responses), [r.text for r in responses]
    assert _ready(client, "s2").json()["watermark"] == 5
    events = _ready(client, "s2").json()["events"]
    assert [e["sequence"] for e in events] == [1, 2, 3, 4, 5]
