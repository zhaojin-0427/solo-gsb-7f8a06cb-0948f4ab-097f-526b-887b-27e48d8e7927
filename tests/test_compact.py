"""End-to-end tests for confirmed-prefix compaction."""

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


def _ready(client, stream_id, after_seq=0):
    return client.get(
        f"/streams/{stream_id}/ready", params={"after_seq": after_seq}
    )


def _claim(client, stream_id):
    return client.post(f"/streams/{stream_id}/claim")


def _ack(client, stream_id, token):
    return client.post(
        f"/streams/{stream_id}/ack", json={"token": token}
    )


def _compact(client, stream_id, through_seq):
    return client.post(
        f"/streams/{stream_id}/compact", json={"through_seq": through_seq}
    )


def _confirm_events(client, stream_id, *sequences):
    for expected in sequences:
        claim = _claim(client, stream_id)
        assert claim.status_code == 200, claim.text
        assert claim.json()["sequence"] == expected
        ack = _ack(client, stream_id, claim.json()["token"])
        assert ack.status_code == 200, ack.text
        assert ack.json()["confirmed_seq"] == expected


# --- request validation ------------------------------------------------------


def test_compact_unknown_stream_allows_only_zero(client):
    resp = _compact(client, "ghost", 0)
    assert resp.status_code == 200, resp.text
    assert resp.json() == {
        "ok": True,
        "stream_id": "ghost",
        "compacted_until": 0,
        "confirmed_seq": 0,
    }

    resp = _compact(client, "ghost", 1)
    assert resp.status_code == 409
    detail = resp.json()["detail"]
    assert detail["error"] == "compact_ahead_of_confirmed"
    assert detail["compacted_until"] == 0


def test_compact_rejects_negative_and_non_integer(client):
    assert _compact(client, "s", -1).status_code == 422
    # Floats (even whole-valued), booleans and strings are not accepted:
    # the input must be a JSON integer.
    for bad in (1.0, 1.5, True, "2"):
        resp = client.post("/streams/s/compact", json={"through_seq": bad})
        assert resp.status_code == 422, bad
    assert client.post("/streams/s/compact", json={}).status_code == 422


# --- bound semantics ---------------------------------------------------------


def test_compact_requires_confirmed_prefix(client):
    for i in range(1, 4):
        assert _submit(client, "s", i, {"v": i}).status_code == 200

    # Nothing confirmed yet.
    resp = _compact(client, "s", 1)
    assert resp.status_code == 409
    detail = resp.json()["detail"]
    assert detail["error"] == "compact_ahead_of_confirmed"
    assert detail["compacted_until"] == 0
    # Refusal deleted nothing.
    assert [e["sequence"] for e in _ready(client, "s").json()["events"]] == [
        1, 2, 3
    ]

    _confirm_events(client, "s", 1)
    resp = _compact(client, "s", 2)
    assert resp.status_code == 409
    assert resp.json()["detail"]["error"] == "compact_ahead_of_confirmed"


def test_compact_deletes_prefix_and_returns_bound(client):
    for i in range(1, 5):
        _submit(client, "s", i, {"v": i})
    _confirm_events(client, "s", 1, 2, 3)

    resp = _compact(client, "s", 3)
    assert resp.status_code == 200, resp.text
    assert resp.json() == {
        "ok": True,
        "stream_id": "s",
        "compacted_until": 3,
        "confirmed_seq": 3,
    }

    ready = _ready(client, "s", after_seq=3).json()
    assert ready["watermark"] == 4
    assert ready["events"] == [{"sequence": 4, "data": {"v": 4}}]


def test_compact_is_idempotent_below_or_at_old_bound(client):
    for i in range(1, 4):
        _submit(client, "s", i, {"v": i})
    _confirm_events(client, "s", 1, 2)

    assert _compact(client, "s", 2).json()["compacted_until"] == 2
    for through in (2, 1, 0):
        resp = _compact(client, "s", through)
        assert resp.status_code == 200
        assert resp.json()["compacted_until"] == 2
        assert resp.json()["confirmed_seq"] == 2

    # The deleted prefix stays deleted (resume from the bound).
    assert [
        e["sequence"] for e in _ready(client, "s", after_seq=2).json()["events"]
    ] == [3]


def test_ready_returns_410_with_bound_below_compacted_until(client):
    for i in range(1, 5):
        _submit(client, "s", i, {"v": i})
    _confirm_events(client, "s", 1, 2, 3)
    assert _compact(client, "s", 3).status_code == 200

    # after_seq strictly below the bound -> 410 carrying the bound.
    for after_seq in (0, 1, 2):
        resp = _ready(client, "s", after_seq=after_seq)
        assert resp.status_code == 410, after_seq
        detail = resp.json()["detail"]
        assert detail["error"] == "already_compacted"
        assert detail["compacted_until"] == 3

    # at or above the bound: normal reads resume.
    resp = _ready(client, "s", after_seq=3)
    assert resp.status_code == 200
    body = resp.json()
    assert body["watermark"] == 4
    assert body["events"] == [{"sequence": 4, "data": {"v": 4}}]

    resp = _ready(client, "s", after_seq=4)
    assert resp.status_code == 200
    assert resp.json()["events"] == []


def test_410_points_at_resume_point_after_further_compact(client):
    for i in range(1, 6):
        _submit(client, "s", i, {"v": i})
    _confirm_events(client, "s", 1, 2, 3, 4)
    _compact(client, "s", 2)
    assert _ready(client, "s", after_seq=0).status_code == 410
    assert _ready(client, "s", after_seq=2).status_code == 200

    # Bound advances; the previously-valid after_seq=2 is now stale.
    _compact(client, "s", 4)
    resp = _ready(client, "s", after_seq=2)
    assert resp.status_code == 410
    assert resp.json()["detail"]["compacted_until"] == 4
    resumed = _ready(client, "s", after_seq=4)
    assert [e["sequence"] for e in resumed.json()["events"]] == [5]


# --- ingestion / claim after compaction --------------------------------------


def test_resubmitting_compacted_sequence_conflicts_and_keeps_nonce(client):
    for i in range(1, 3):
        _submit(client, "s", i, {"v": i})
    _confirm_events(client, "s", 1, 2)
    _compact(client, "s", 2)

    nonce = uuid.uuid4().hex
    bad = _event_payload("s", 2, {"v": 99}, nonce=nonce)
    resp = client.post("/streams/events", json=bad)
    assert resp.status_code == 409
    assert resp.json()["detail"]["error"] == "duplicate_sequence"

    # Same nonce still accepted for a new sequence.
    good = _event_payload("s", 3, {"v": 3}, nonce=nonce)
    resp = client.post("/streams/events", json=good)
    assert resp.status_code == 200, resp.text
    assert resp.json()["opened"] == [3]


def test_claim_continues_from_compacted_bound(client):
    for i in range(1, 5):
        _submit(client, "s", i, {"v": i})
    _confirm_events(client, "s", 1, 2)
    _compact(client, "s", 2)

    # Claim resumes at confirmed_seq + 1 == 3, unaffected by deletion.
    claim = _claim(client, "s")
    assert claim.status_code == 200
    assert claim.json()["sequence"] == 3
    assert claim.json()["data"] == {"v": 3}
    assert _ack(client, "s", claim.json()["token"]).status_code == 200

    # Compact further, then keep consuming.
    _compact(client, "s", 3)
    claim = _claim(client, "s")
    assert claim.json()["sequence"] == 4


def test_compact_persists_across_client_restart(tmp_path, monkeypatch):
    monkeypatch.setenv("WEBHOOK_SECRET", SECRET)
    db_path = str(tmp_path / "nonces.db")
    monkeypatch.setenv("NONCE_DB_PATH", db_path)

    with TestClient(app) as first:
        for i in range(1, 4):
            _submit(first, "s", i, {"v": i})
        _confirm_events(first, "s", 1, 2)
        assert _compact(first, "s", 2).status_code == 200

    # Reopen against the same database file.
    with TestClient(app) as second:
        resp = _ready(second, "s")
        assert resp.status_code == 410
        assert resp.json()["detail"]["compacted_until"] == 2
        resumed = _ready(second, "s", after_seq=2)
        assert [e["sequence"] for e in resumed.json()["events"]] == [3]
        assert _compact(second, "s", 1).json()["compacted_until"] == 2


# --- concurrency: consistent snapshots ---------------------------------------


def test_concurrent_compact_and_reads_never_show_a_gap(client):
    for i in range(1, 101):
        _submit(client, "s", i, {"v": i})
    _confirm_events(client, "s", *range(1, 61))

    errors = []
    barrier = threading.Barrier(4)

    def reader():
        barrier.wait()
        for _ in range(200):
            resp = _ready(client, "s")
            if resp.status_code == 410:
                bound = resp.json()["detail"]["compacted_until"]
                if bound <= 0:
                    errors.append("410 with non-positive bound")
                continue
            assert resp.status_code == 200, resp.text
            body = resp.json()
            seqs = [e["sequence"] for e in body["events"]]
            watermark = body["watermark"]
            # after_seq=0: a 200 with an already-compacted prefix would
            # have to start above 1 (missing prefix), and the shown tail
            # must be contiguous up to the watermark (no holes).
            if seqs and seqs[0] != 1:
                errors.append(f"missing prefix without 410: {seqs[:5]}")
            if seqs and seqs != list(range(seqs[0], watermark + 1)):
                errors.append(f"hole in events: {seqs[:5]}")

    def compactor():
        barrier.wait()
        for through in range(0, 61):
            resp = _compact(client, "s", through)
            if resp.status_code not in (200, 409):
                errors.append(f"unexpected compact status {resp.status_code}")

    with ThreadPoolExecutor(max_workers=4) as pool:
        futures = [pool.submit(reader) for _ in range(3)]
        futures.append(pool.submit(compactor))
        for future in futures:
            future.result()

    assert errors == []
    assert _compact(client, "s", 60).json()["compacted_until"] == 60
