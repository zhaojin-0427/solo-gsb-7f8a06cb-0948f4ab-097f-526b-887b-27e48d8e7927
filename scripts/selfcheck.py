#!/usr/bin/env python3
"""Stdlib-only self-check for the core logic (no FastAPI required).

Run:  python3 scripts/selfcheck.py
Exercises signing/canonicalization vectors and the atomic nonce store,
and simulates the full /verify decision flow (timestamp -> signature ->
nonce) the same way app.main does.
"""

import hashlib
import hmac
import json
import os
import sqlite3
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.db import ChainCorruptionError, NonceStore
from app.events import EventBodyError, parse_event_body
from app.integrity import (
    DIGEST_FORMAT_ARRAY_V2,
    ZERO_DIGEST,
    canonical_event_bytes,
    chain_digest,
    legacy_chain_digest,
)
from app.signing import (
    build_canonical_string,
    canonical_query,
    percent_encode,
    verify_signature,
)

SECRET = b"selfcheck-secret"
failures = []


def check(name, cond):
    print(f"{'PASS' if cond else 'FAIL'}  {name}")
    if not cond:
        failures.append(name)


# --- percent encoding -------------------------------------------------------
check("unreserved chars untouched",
      percent_encode("abcXYZ019-._~") == "abcXYZ019-._~")
check("reserved chars encoded",
      percent_encode("a b&c=d/e") == "a%20b%26c%3Dd%2Fe")
check("utf-8 uppercase hex", percent_encode("café") == "caf%C3%A9")

# --- canonical query --------------------------------------------------------
check("sort by key then value, duplicates kept",
      canonical_query([("b", "2"), ("a", "1"), ("a", "0"), ("b", "10")])
      == "a=0&a=1&b=10&b=2")
check("encode before sort",
      canonical_query([("sp ace", "a&b"), ("a", "1")]) == "a=1&sp%20ace=a%26b")
check("empty query", canonical_query([]) == "")

# --- canonical string & HMAC ------------------------------------------------
body = '{"event":"ping"}'
ts = int(time.time())
nonce = "nonce-001"
canonical = build_canonical_string(
    method="POST", path="/webhook",
    query_items=[("b", "2"), ("a", "1"), ("a", "0")],
    body=body, timestamp=ts, nonce=nonce,
)
expected = "\n".join([
    "POST", "/webhook", "a=0&a=1&b=2",
    hashlib.sha256(body.encode()).hexdigest(), str(ts), nonce,
])
check("canonical string layout", canonical == expected)

sig = hmac.new(SECRET, canonical.encode(), hashlib.sha256).hexdigest()
check("good signature verifies", verify_signature(SECRET, sig, canonical))
check("wrong secret rejected", not verify_signature(b"other", sig, canonical))
check("tampered canonical rejected",
      not verify_signature(SECRET, sig, canonical + "x"))
check("uppercase hex rejected", not verify_signature(SECRET, sig.upper(), canonical))
check("garbage hex rejected", not verify_signature(SECRET, "zz" * 32, canonical))

# --- nonce store ------------------------------------------------------------
with tempfile.TemporaryDirectory() as tmp:
    store = NonceStore(os.path.join(tmp, "nonces.db"))
    check("first registration succeeds", store.register(nonce, "POST", "/webhook", ts))
    check("replay rejected", not store.register(nonce, "POST", "/webhook", ts))
    check("distinct nonce ok", store.register("nonce-002", "POST", "/webhook", ts))
    reopened = NonceStore(os.path.join(tmp, "nonces.db"))
    check("nonce persists across reopen",
          not reopened.register(nonce, "POST", "/webhook", ts))

# --- simulated /verify flow (same order as app.main) ------------------------
def simulate_verify(payload, store, secret=SECRET, now=None, window=300):
    now = int(time.time()) if now is None else now
    if abs(now - payload["timestamp"]) > window:
        return 401, "timestamp_out_of_window"
    canonical = build_canonical_string(
        method=payload["method"].upper(), path=payload["path"],
        query_items=[(k, v) for k, v in payload["query"]],
        body=payload["body"], timestamp=payload["timestamp"],
        nonce=payload["nonce"],
    )
    if not verify_signature(secret, payload["signature"], canonical):
        return 401, "invalid_signature"
    if not store.register(payload["nonce"], payload["method"].upper(),
                          payload["path"], now):
        return 409, "replayed_nonce"
    return 200, "verified"


def make_payload(secret=SECRET, **kw):
    p = {"method": "post", "path": "/webhook",
         "query": [("b", "2"), ("a", "1"), ("a", "0")],
         "body": body, "timestamp": int(time.time()), "nonce": "n-" + str(time.time_ns())}
    p.update(kw)
    c = build_canonical_string(p["method"].upper(), p["path"], p["query"],
                               p["body"], p["timestamp"], p["nonce"])
    p["signature"] = hmac.new(secret, c.encode(), hashlib.sha256).hexdigest()
    return p


with tempfile.TemporaryDirectory() as tmp:
    store = NonceStore(os.path.join(tmp, "flow.db"))
    p1 = make_payload()
    check("flow: valid -> 200", simulate_verify(p1, store) == (200, "verified"))
    check("flow: replay -> 409", simulate_verify(p1, store) == (409, "replayed_nonce"))

    p2 = make_payload(secret=b"wrong-secret")
    check("flow: bad sig -> 401 invalid_signature",
          simulate_verify(p2, store)[1] == "invalid_signature")
    p2_fixed = make_payload(nonce=p2["nonce"])
    check("flow: failed sig does not consume nonce",
          simulate_verify(p2_fixed, store) == (200, "verified"))

    p3 = make_payload(timestamp=int(time.time()) - 301)
    check("flow: stale ts -> 401 timestamp_out_of_window",
          simulate_verify(p3, store)[1] == "timestamp_out_of_window")
    p3_fixed = make_payload(nonce=p3["nonce"])
    check("flow: stale ts does not consume nonce",
          simulate_verify(p3_fixed, store) == (200, "verified"))

# --- event body parsing -----------------------------------------------------
def event_body(stream_id, sequence, data):
    return json.dumps({"stream_id": stream_id, "sequence": sequence, "data": data})


ev = parse_event_body(event_body("s1", 1, {"x": [1, 2]}))
check("event body parsed", ev.stream_id == "s1" and ev.sequence == 1
      and ev.data == {"x": [1, 2]})

for bad in ["", "not-json", "[]", "42", "null", "{}",
            event_body("", 1, {}), event_body(5, 1, {}),
            event_body("s", 0, {}), event_body("s", 1.0, {}),
            event_body("s", True, {}),
            '{"stream_id":"s","sequence":1}',
            '{"stream_id":"s","data":1}',
            '{"sequence":1,"data":1}']:
    try:
        parse_event_body(bad)
        check(f"event body rejected: {bad[:30]!r}", False)
    except EventBodyError:
        check(f"event body rejected: {bad[:30]!r}", True)

# --- stream store: buffering, gap fill, conflicts, shared nonce -------------
with tempfile.TemporaryDirectory() as tmp:
    store = NonceStore(os.path.join(tmp, "streams.db"))

    def submit(nonce, stream, sequence, data=None):
        return store.store_stream_event(
            nonce=nonce, method="POST", path="/streams/events", now=ts,
            stream_id=stream, sequence=sequence, data=data,
        )

    check("out-of-order seq 3 buffered", submit("e3", "s", 3) == ("ok", [], 0))
    check("seq 3 not readable", store.ready_events("s", 0) == (0, 0, []))
    check("out-of-order seq 2 buffered", submit("e2", "s", 2) == ("ok", [], 0))
    check("gap fill opens 1,2,3",
          submit("e1", "s", 1) == ("ok", [1, 2, 3], 3))
    check("ready order",
          [e["sequence"] for e in store.ready_events("s", 1)[2]] == [2, 3])
    check("read is non-destructive",
          len(store.ready_events("s", 0)[2]) == 3)
    check("duplicate buffered/ready seq conflicts",
          submit("dup", "s", 2)[0] == "duplicate_sequence")
    check("conflict does not consume nonce",
          submit("dup", "s", 4) == ("ok", [4], 4))
    store.register("shared", "POST", "/verify", ts)
    check("nonce shared with /verify",
          submit("shared", "s", 5)[0] == "replayed_nonce")
    check("replay stores nothing", store.ready_events("s", 4)[2] == [])
    check("unknown stream empty", store.ready_events("other", 0) == (0, 0, []))
    check("streams independent",
          submit("b1", "t", 1, "你好") == ("ok", [1], 1))
    _, _, evs = store.ready_events("t", 0)
    check("unicode data round trip", evs == [{"sequence": 1, "data": "你好"}])

    # --- resumable claim / ack on the same store ------------------------
    status, claim = store.claim_next_event("t", now=ts)
    check("claim next open event",
          status == "claimed" and claim["sequence"] == 1
          and claim["data"] == "你好" and claim["token"]
          and claim["expires_at"] == ts + store.lease_ttl_seconds)
    check("live lease blocks reclaim",
          store.claim_next_event("t", now=ts)[0] == "leased")
    check("wrong token rejected",
          store.acknowledge_lease("t", "nope", now=ts)[0] == "invalid_token")
    check("ack on a stream without lease rejected",
          store.acknowledge_lease("u", "x", now=ts)[0] == "no_lease")
    check("expired lease rejected and not advanced",
          store.acknowledge_lease(
              "t", claim["token"], now=ts + store.lease_ttl_seconds
          )[0] == "lease_expired")
    old_token = claim["token"]
    status, redelivered = store.claim_next_event(
        "t", now=ts + store.lease_ttl_seconds
    )
    check("expired lease redelivers same seq with rotated token",
          status == "claimed" and redelivered["sequence"] == 1
          and redelivered["token"] != old_token)
    check("old token no longer valid",
          store.acknowledge_lease("t", old_token, now=ts + 40)[0]
          == "invalid_token")
    check("new token acknowledges",
          store.acknowledge_lease(
              "t", redelivered["token"], now=ts + 40
          ) == ("acknowledged", 1))
    check("duplicate ack rejected",
          store.acknowledge_lease(
              "t", redelivered["token"], now=ts + 40
          )[0] == "no_lease")
    check("drained stream has nothing to claim",
          store.claim_next_event("t", now=ts + 40)[0] == "empty")
    # A stream with only a buffered (gap-behind) event has nothing open.
    submit("g2", "g", 2)
    check("claim never crosses watermark",
          store.claim_next_event("g", now=ts + 40)[0] == "empty")
    # Claim before reopen, then the token must still ack after reopen.
    submit("c1", "r", 1, "restart")
    _, pending = store.claim_next_event("r", now=ts + 40)
    check("pending lease survives reopen and token still acks",
          NonceStore(os.path.join(tmp, "streams.db")).acknowledge_lease(
              "r", pending["token"], now=ts + 41
          ) == ("acknowledged", 1))

    # --- prefix compaction ----------------------------------------------
    for i in range(1, 4):
        submit(f"k{i}", "k", i, {"v": i})
    # Nothing confirmed yet: compaction beyond 0 is refused, even at 0...
    check("compact ahead of confirmed refused",
          store.compact_stream("k", 1)
          == ("ahead_of_confirmed", 0, 0))
    check("unknown stream accepts only through_seq=0",
          store.compact_stream("zz", 0) == ("ok", 0, 0))
    check("unknown stream rejects through_seq>0",
          store.compact_stream("zz", 1)
          == ("ahead_of_confirmed", 0, 0))
    # Confirm 1 and 2 in order, then compact through 2.
    for expected in (1, 2):
        _, lease = store.claim_next_event("k", now=ts + 50)
        check("claim before compact", lease["sequence"] == expected)
        check("ack before compact",
              store.acknowledge_lease(
                  "k", lease["token"], now=ts + 50
              ) == ("acknowledged", expected))
    check("compact through confirmed prefix",
          store.compact_stream("k", 2) == ("ok", 2, 2))
    check("compaction is idempotent and monotonic",
          store.compact_stream("k", 1) == ("ok", 2, 2))
    check("compacted events gone, later ones kept",
          store.ready_events("k", 0)
          == (2, 3, [{"sequence": 3, "data": {"v": 3}}]))
    check("read below the bound is flagged",
          store.ready_events("k", 1)[0] == 2)
    # Re-sending a compacted-away signed sequence is still a duplicate and
    # does not consume the nonce.
    check("compacted sequence still conflicts",
          submit("kdup", "k", 2)[0] == "duplicate_sequence")
    check("duplicate after compact keeps nonce",
          submit("kdup", "k", 4) == ("ok", [4], 4))
    check("compaction survives reopen",
          NonceStore(os.path.join(tmp, "streams.db")).ready_events("k", 0)
          == (2, 4, [
              {"sequence": 3, "data": {"v": 3}},
              {"sequence": 4, "data": None},
          ]))
    # Cannot compact past the confirmed cursor; ack 3 then advance to 3.
    check("cannot compact the unconfirmed event",
          store.compact_stream("k", 4)
          == ("ahead_of_confirmed", 2, 2))
    _, lease = store.claim_next_event("k", now=ts + 60)
    check("claim resumes after the bound", lease["sequence"] == 3)

# --- integrity hash chain ----------------------------------------------------

# Canonical bytes are the compact UTF-8 JSON of the [stream_id, sequence,
# data] array, with nested object keys sorted.
check("canonical event bytes",
      canonical_event_bytes("s", 2, {"z": 1, "a": "中"})
      == b'["s",2,{"a":"\xe4\xb8\xad","z":1}]')
check("legacy object bytes differ",
      legacy_chain_digest(ZERO_DIGEST, "s", 2, {"z": 1, "a": "中"})
      != chain_digest(ZERO_DIGEST, "s", 2, {"z": 1, "a": "中"}))

with tempfile.TemporaryDirectory() as tmp:
    store = NonceStore(os.path.join(tmp, "integrity.db"))

    def isubmit(nonce, stream, sequence, data=None):
        return store.store_stream_event(
            nonce=nonce, method="POST", path="/streams/events", now=ts,
            stream_id=stream, sequence=sequence, data=data,
        )

    # Buffered events produce no chain.
    check("buffered seq 3 not linked", isubmit("i3", "i", 3, {"v": 3})[1] == [])
    check("empty chain while gap open",
          store.stream_integrity("i") == (0, 0, ZERO_DIGEST, None))
    isubmit("i2", "i", 2, {"v": 2})
    check("still empty chain behind gap",
          store.stream_integrity("i")[3] is None
          and store.stream_integrity("i")[1] == 0)

    # Gap fill links 1..3 in order from the zero anchor.
    isubmit("i1", "i", 1, {"v": 1})
    expected = ZERO_DIGEST
    for seq in (1, 2, 3):
        expected = chain_digest(expected, "i", seq, {"v": seq})
    check("chain verifies after gap fill",
          store.stream_integrity("i") == (0, 3, expected, None))

    # Confirm 1,2 and compact through 2: the digest AT 2 is the anchor.
    for seq in (1, 2):
        _, lease = store.claim_next_event("i", now=ts + 70)
        check("integrity claim order", lease["sequence"] == seq)
        check("integrity ack",
              store.acknowledge_lease("i", lease["token"], now=ts + 70)
              == ("acknowledged", seq))
    check("compact with anchor", store.compact_stream("i", 2) == ("ok", 2, 2))
    anchor = chain_digest(
        chain_digest(ZERO_DIGEST, "i", 1, {"v": 1}), "i", 2, {"v": 2}
    )
    db_path = os.path.join(tmp, "integrity.db")
    conn = sqlite3.connect(db_path)
    links = [row[0] for row in conn.execute(
        "SELECT sequence FROM stream_digests WHERE stream_id='i' ORDER BY sequence"
    )]
    check("digest at bound retained as anchor", links == [2, 3])
    conn.close()

    # Verification restarts from the anchor; events continue from it.
    compacted, watermark, tail, invalid = store.stream_integrity("i")
    check("verify from retained anchor",
          (compacted, watermark, invalid) == (2, 3, None) and tail == expected)
    isubmit("i4", "i", 4, {"v": 4})
    compacted, watermark, tail, invalid = store.stream_integrity("i")
    check("chain continues after compaction",
          (compacted, watermark, invalid) == (2, 4, None)
          and tail == chain_digest(expected, "i", 4, {"v": 4}))

    # Tamper a stored link: the first mismatching sequence is reported.
    conn = sqlite3.connect(db_path)
    conn.execute("UPDATE stream_digests SET digest=? WHERE stream_id='i' "
                 "AND sequence=3", (b"\xab" * 32,))
    conn.commit()
    conn.close()
    compacted, watermark, tail, invalid = store.stream_integrity("i")
    check("tampered digest detected", invalid == 3 and tail == anchor)

    # Unknown stream: empty chain.
    check("unknown stream empty chain",
          store.stream_integrity("nobody") == (0, 0, ZERO_DIGEST, None))

# --- legacy database upgrade -------------------------------------------------
with tempfile.TemporaryDirectory() as tmp:
    db_path = os.path.join(tmp, "legacy.db")
    conn = sqlite3.connect(db_path)
    conn.executescript("""
        CREATE TABLE used_nonces (nonce TEXT PRIMARY KEY, method TEXT NOT NULL,
            path TEXT NOT NULL, seen_at INTEGER NOT NULL);
        CREATE TABLE stream_events (stream_id TEXT NOT NULL,
            sequence INTEGER NOT NULL CHECK (sequence >= 1),
            data_json TEXT NOT NULL, nonce TEXT NOT NULL, seen_at INTEGER NOT NULL,
            PRIMARY KEY (stream_id, sequence));
        CREATE TABLE stream_watermarks (stream_id TEXT PRIMARY KEY,
            high_water INTEGER NOT NULL CHECK (high_water >= 0));
        CREATE TABLE stream_consumers (stream_id TEXT PRIMARY KEY,
            confirmed_seq INTEGER NOT NULL CHECK (confirmed_seq >= 0));
        CREATE TABLE stream_leases (stream_id TEXT PRIMARY KEY,
            sequence INTEGER NOT NULL CHECK (sequence >= 1),
            token TEXT NOT NULL UNIQUE, expires_at INTEGER NOT NULL);
        CREATE TABLE stream_compactions (stream_id TEXT PRIMARY KEY,
            compacted_until INTEGER NOT NULL CHECK (compacted_until >= 0));
    """)
    for seq in (1, 2, 3):
        conn.execute("INSERT INTO stream_events VALUES (?,?,?,?,?)",
                     ("s", seq, json.dumps({"v": seq}, separators=(",", ":")),
                      f"l{seq}", ts))
    conn.execute("INSERT INTO stream_watermarks VALUES ('s', 3)")
    conn.execute("INSERT INTO stream_consumers VALUES ('s', 1)")
    conn.execute("INSERT INTO stream_leases VALUES ('s', 2, 'legacy-token', ?)",
                 (ts + 3600,))
    conn.execute("DELETE FROM stream_events WHERE stream_id='s' AND sequence<=1")
    conn.execute("INSERT INTO stream_compactions VALUES ('s', 1)")
    conn.commit()
    conn.close()

    migrated = NonceStore(db_path)
    d2 = chain_digest(ZERO_DIGEST, "s", 2, {"v": 2})
    d3 = chain_digest(d2, "s", 3, {"v": 3})
    check("legacy backfill from bound",
          migrated.stream_integrity("s") == (1, 3, d3, None))
    conn = sqlite3.connect(db_path)
    anchor_row = conn.execute(
        "SELECT digest FROM stream_digests WHERE stream_id='s' AND sequence=1"
    ).fetchone()
    marker_row = conn.execute(
        "SELECT value FROM app_meta WHERE key='digest_format'"
    ).fetchone()
    conn.close()
    check("legacy backfill sets zero anchor at bound",
          anchor_row is not None and anchor_row[0] == ZERO_DIGEST)
    check("backfill records the array format marker",
          marker_row is not None and marker_row[0] == DIGEST_FORMAT_ARRAY_V2)
    # Lease and consumption progress survived untouched.
    check("legacy lease survives upgrade",
          migrated.acknowledge_lease("s", "legacy-token", now=ts + 1)
          == ("acknowledged", 2))
    check("legacy consumer cursor survives upgrade",
          migrated.compact_stream("s", 0) == ("ok", 1, 2))
    check("legacy upgrade runs once",
          NonceStore(db_path).stream_integrity("s") == (1, 3, d3, None))

# --- object-format chain migration -------------------------------------------
def build_object_format_db(db_path, corrupt=False):
    """A database as the pre-fix code left it: object-encoding digests
    and no app_meta marker table."""
    conn = sqlite3.connect(db_path)
    conn.executescript("""
        CREATE TABLE used_nonces (nonce TEXT PRIMARY KEY, method TEXT NOT NULL,
            path TEXT NOT NULL, seen_at INTEGER NOT NULL);
        CREATE TABLE stream_events (stream_id TEXT NOT NULL,
            sequence INTEGER NOT NULL CHECK (sequence >= 1),
            data_json TEXT NOT NULL, nonce TEXT NOT NULL, seen_at INTEGER NOT NULL,
            PRIMARY KEY (stream_id, sequence));
        CREATE TABLE stream_watermarks (stream_id TEXT PRIMARY KEY,
            high_water INTEGER NOT NULL CHECK (high_water >= 0));
        CREATE TABLE stream_consumers (stream_id TEXT PRIMARY KEY,
            confirmed_seq INTEGER NOT NULL CHECK (confirmed_seq >= 0));
        CREATE TABLE stream_leases (stream_id TEXT PRIMARY KEY,
            sequence INTEGER NOT NULL CHECK (sequence >= 1),
            token TEXT NOT NULL UNIQUE, expires_at INTEGER NOT NULL);
        CREATE TABLE stream_compactions (stream_id TEXT PRIMARY KEY,
            compacted_until INTEGER NOT NULL CHECK (compacted_until >= 0));
        CREATE TABLE stream_digests (stream_id TEXT NOT NULL,
            sequence INTEGER NOT NULL CHECK (sequence >= 1),
            digest BLOB NOT NULL,
            PRIMARY KEY (stream_id, sequence));
    """)
    for seq in (1, 2, 3):
        conn.execute("INSERT INTO stream_events VALUES (?,?,?,?,?)",
                     ("s", seq, json.dumps({"v": seq}, separators=(",", ":")),
                      f"o{seq}", ts))
    conn.execute("INSERT INTO stream_watermarks VALUES ('s', 3)")
    previous = ZERO_DIGEST
    for seq in (1, 2, 3):
        previous = legacy_chain_digest(previous, "s", seq, {"v": seq})
        if corrupt and seq == 2:
            previous = b"\xff" * 32
        conn.execute("INSERT INTO stream_digests VALUES (?,?,?)",
                     ("s", seq, previous))
    conn.commit()
    conn.close()


with tempfile.TemporaryDirectory() as tmp:
    db_path = os.path.join(tmp, "object-v1.db")
    build_object_format_db(db_path)
    migrated = NonceStore(db_path)
    expected = ZERO_DIGEST
    for seq in (1, 2, 3):
        expected = chain_digest(expected, "s", seq, {"v": seq})
    check("object-format chain re-encoded at startup",
          migrated.stream_integrity("s") == (0, 3, expected, None))
    conn = sqlite3.connect(db_path)
    marker_row = conn.execute(
        "SELECT value FROM app_meta WHERE key='digest_format'"
    ).fetchone()
    conn.close()
    check("migration records the array format marker",
          marker_row is not None and marker_row[0] == DIGEST_FORMAT_ARRAY_V2)
    check("migration is idempotent on restart",
          NonceStore(db_path).stream_integrity("s") == (0, 3, expected, None))

with tempfile.TemporaryDirectory() as tmp:
    db_path = os.path.join(tmp, "corrupt-v1.db")
    build_object_format_db(db_path, corrupt=True)
    conn = sqlite3.connect(db_path)
    before = conn.execute(
        "SELECT sequence, digest FROM stream_digests ORDER BY sequence"
    ).fetchall()
    conn.close()
    try:
        NonceStore(db_path)
        check("corrupted legacy chain aborts startup", False)
    except ChainCorruptionError:
        check("corrupted legacy chain aborts startup", True)
    conn = sqlite3.connect(db_path)
    after = conn.execute(
        "SELECT sequence, digest FROM stream_digests ORDER BY sequence"
    ).fetchall()
    marker_count = conn.execute(
        "SELECT COUNT(*) FROM app_meta"
    ).fetchone()[0]
    conn.close()
    check("corrupted chain left untouched (no silent rewrite)",
          after == before and marker_count == 0)

print()
if failures:
    print(f"{len(failures)} check(s) FAILED")
    sys.exit(1)
print("All checks passed.")
