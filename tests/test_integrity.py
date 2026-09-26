"""Unit and end-to-end tests for the integrity hash chain."""

import hashlib
import hmac
import json
import sqlite3
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor

import pytest
from fastapi.testclient import TestClient

from app.db import ChainCorruptionError, NonceStore
from app.integrity import (
    DIGEST_FORMAT_ARRAY_V2,
    DIGEST_LEN,
    ZERO_DIGEST,
    canonical_event_bytes,
    chain_digest,
    legacy_chain_digest,
    legacy_object_event_bytes,
)
from app.main import app
from app.signing import build_canonical_string


def test_zero_digest_is_32_zero_bytes():
    assert ZERO_DIGEST == b"\x00" * 32
    assert len(ZERO_DIGEST) == DIGEST_LEN


def test_canonical_event_bytes_are_compact_sorted_utf8():
    raw = canonical_event_bytes("s1", 7, {"z": 1, "a": [1, 2], "中": "文"})
    # The top level is the [stream_id, sequence, data] array (no keys);
    # nested object keys are sorted; no whitespace; non-ASCII is emitted
    # as raw UTF-8 bytes.
    assert raw == (
        b'["s1",7,{"a":[1,2],"z":1,"\xe4\xb8\xad":"\xe6\x96\x87"}]'
    )
    # And it is exactly json.dumps of the array with the documented
    # keyword arguments.
    assert raw == json.dumps(
        ["s1", 7, {"z": 1, "a": [1, 2], "中": "文"}],
        ensure_ascii=False, separators=(",", ":"), sort_keys=True,
    ).encode("utf-8")


def test_canonical_bytes_cover_every_json_data_shape():
    for data in (None, True, 42, 3.5, "str", [1, 2], {"n": {"x": [True, None]}}):
        assert canonical_event_bytes("s", 1, data) == json.dumps(
            ["s", 1, data],
            ensure_ascii=False, separators=(",", ":"), sort_keys=True,
        ).encode("utf-8")


def test_legacy_object_event_bytes_keep_the_old_object_shape():
    # The pre-fix encoding hashed the three-key object; it is retained
    # only for verifying stored legacy chains during the migration.
    assert legacy_object_event_bytes("s1", 7, {"z": 1, "a": "中"}) == (
        b'{"data":{"a":"\xe4\xb8\xad","z":1},"sequence":7,'
        b'"stream_id":"s1"}'
    )
    # The two encodings must never collide for the same event.
    assert legacy_object_event_bytes("s1", 7, {}) != canonical_event_bytes(
        "s1", 7, {}
    )
    assert legacy_chain_digest(ZERO_DIGEST, "s", 1, {"v": 1}) != chain_digest(
        ZERO_DIGEST, "s", 1, {"v": 1}
    )


def test_chain_digest_matches_independent_sha256_vector():
    first = chain_digest(ZERO_DIGEST, "s", 1, {"v": 1})
    expected_first = hashlib.sha256(
        ZERO_DIGEST + canonical_event_bytes("s", 1, {"v": 1})
    ).digest()
    assert first == expected_first
    assert len(first) == 32

    second = chain_digest(first, "s", 2, {"v": 2})
    assert second == hashlib.sha256(
        first + canonical_event_bytes("s", 2, {"v": 2})
    ).digest()
    assert second != first


def test_different_data_or_position_breaks_the_link():
    base = chain_digest(ZERO_DIGEST, "s", 1, {"v": 1})
    assert chain_digest(ZERO_DIGEST, "s", 1, {"v": 2}) != base
    assert chain_digest(ZERO_DIGEST, "s", 2, {"v": 1}) != base
    assert chain_digest(ZERO_DIGEST, "t", 1, {"v": 1}) != base


def test_chain_digest_rejects_bad_previous_length():
    with pytest.raises(ValueError):
        chain_digest(b"too-short", "s", 1, {})
    with pytest.raises(ValueError):
        chain_digest(b"\x00" * 31, "s", 1, {})


# --- store: digest creation, gap fills, compaction anchor --------------------


def _submit(store, nonce, stream_id, sequence, data=None, now=1_700_000_000):
    return store.store_stream_event(
        nonce=nonce, method="POST", path="/streams/events", now=now,
        stream_id=stream_id, sequence=sequence, data=data,
    )


def _digest_rows(path, stream_id):
    conn = sqlite3.connect(path)
    try:
        return conn.execute(
            "SELECT sequence, digest FROM stream_digests "
            "WHERE stream_id = ? ORDER BY sequence",
            (stream_id,),
        ).fetchall()
    finally:
        conn.close()


def test_buffered_events_get_no_digest_until_gap_filled(tmp_path):
    path = str(tmp_path / "nonces.db")
    store = NonceStore(path)
    _submit(store, "n3", "s", 3, {"v": 3})
    _submit(store, "n2", "s", 2, {"v": 2})
    # Still gap at 1: no links exist for the buffered events.
    assert _digest_rows(path, "s") == []
    assert store.stream_integrity("s") == (0, 0, ZERO_DIGEST, None)

    _submit(store, "n1", "s", 1, {"v": 1})
    rows = _digest_rows(path, "s")
    assert [sequence for sequence, _ in rows] == [1, 2, 3]

    # Recomputed chain agrees with the stored links and ends at seq 3.
    compacted, watermark, tail, invalid = store.stream_integrity("s")
    assert (compacted, watermark, invalid) == (0, 3, None)
    assert tail == rows[-1][1]
    expected = ZERO_DIGEST
    for sequence, stored in rows:
        expected = chain_digest(expected, "s", sequence, {"v": sequence})
        assert stored == expected
    assert tail == expected


def test_second_gap_fill_chains_from_previous_tail(tmp_path):
    store = NonceStore(str(tmp_path / "nonces.db"))
    _submit(store, "n1", "s", 1, "a")
    _submit(store, "n3", "s", 3, "c")  # buffered
    _, _, tail, _ = store.stream_integrity("s")
    # Filling seq 2 must chain seq 2 and the buffered seq 3 from seq 1.
    _submit(store, "n2", "s", 2, "b")
    compacted, watermark, new_tail, invalid = store.stream_integrity("s")
    assert (compacted, watermark, invalid) == (0, 3, None)
    assert new_tail != tail
    expected = chain_digest(
        chain_digest(chain_digest(ZERO_DIGEST, "s", 1, "a"), "s", 2, "b"),
        "s", 3, "c",
    )
    assert new_tail == expected


def test_streams_have_independent_chains(tmp_path):
    store = NonceStore(str(tmp_path / "nonces.db"))
    _submit(store, "a1", "a", 1, {"v": 1})
    _submit(store, "b1", "b", 1, {"v": 1})
    _, _, tail_a, invalid_a = store.stream_integrity("a")
    _, _, tail_b, invalid_b = store.stream_integrity("b")
    assert invalid_a is None and invalid_b is None
    # Same data, different stream_id -> different links.
    assert tail_a != tail_b
    assert tail_a == chain_digest(ZERO_DIGEST, "a", 1, {"v": 1})
    assert tail_b == chain_digest(ZERO_DIGEST, "b", 1, {"v": 1})


def test_compact_retains_digest_at_bound_as_anchor(tmp_path):
    path = str(tmp_path / "nonces.db")
    store = NonceStore(path)
    for i in range(1, 6):
        _submit(store, f"n{i}", "s", i, {"v": i})
    for expected in range(1, 4):
        _, claim = store.claim_next_event("s", now=1_700_000_100)
        assert claim["sequence"] == expected
        assert store.acknowledge_lease(
            "s", claim["token"], now=1_700_000_100
        ) == ("acknowledged", expected)
    assert store.compact_stream("s", 3) == ("ok", 3, 3)

    # Events 1..3 are gone; digest links 1,2 are gone but link 3 survives
    # as the anchor, followed by 4 and 5.
    rows = _digest_rows(path, "s")
    assert [sequence for sequence, _ in rows] == [3, 4, 5]
    conn = sqlite3.connect(path)
    remaining_events = conn.execute(
        "SELECT sequence FROM stream_events WHERE stream_id='s' ORDER BY sequence"
    ).fetchall()
    conn.close()
    assert [row[0] for row in remaining_events] == [4, 5]

    compacted, watermark, tail, invalid = store.stream_integrity("s")
    assert (compacted, watermark, invalid) == (3, 5, None)
    assert tail == rows[-1][1]


def test_chain_continues_from_anchor_after_compaction(tmp_path):
    store = NonceStore(str(tmp_path / "nonces.db"))
    for i in range(1, 4):
        _submit(store, f"n{i}", "s", i, {"v": i})
    for expected in range(1, 3):
        _, claim = store.claim_next_event("s", now=1_700_000_100)
        store.acknowledge_lease("s", claim["token"], now=1_700_000_100)
    store.compact_stream("s", 2)
    _, _, tail_before, _ = store.stream_integrity("s")

    # Newly opened events after compaction link onto the retained anchor.
    assert _submit(store, "n4", "s", 4, {"v": 4}) == ("ok", [4], 4)
    _submit(store, "n6", "s", 6, {"v": 6})  # buffered behind gap 5
    assert _submit(store, "n5", "s", 5, {"v": 5}) == ("ok", [5, 6], 6)
    compacted, watermark, tail, invalid = store.stream_integrity("s")
    assert (compacted, watermark, invalid) == (2, 6, None)
    expected = tail_before
    for sequence in (4, 5, 6):
        expected = chain_digest(expected, "s", sequence, {"v": sequence})
    assert tail == expected


def test_repeated_compaction_advances_the_anchor(tmp_path):
    path = str(tmp_path / "nonces.db")
    store = NonceStore(path)
    for i in range(1, 6):
        _submit(store, f"n{i}", "s", i, {"v": i})
    for expected in range(1, 5):
        _, claim = store.claim_next_event("s", now=1_700_000_100)
        store.acknowledge_lease("s", claim["token"], now=1_700_000_100)
    assert store.compact_stream("s", 2)[0] == "ok"
    assert [s for s, _ in _digest_rows(path, "s")] == [2, 3, 4, 5]
    assert store.compact_stream("s", 4)[0] == "ok"
    # One anchor remains at the new bound.
    assert [s for s, _ in _digest_rows(path, "s")] == [4, 5]
    compacted, _, tail, invalid = store.stream_integrity("s")
    assert compacted == 4 and invalid is None


def test_integrity_flags_tampered_digest_and_then_recovers(tmp_path):
    path = str(tmp_path / "nonces.db")
    store = NonceStore(path)
    for i in range(1, 5):
        _submit(store, f"n{i}", "s", i, {"v": i})

    conn = sqlite3.connect(path)
    conn.execute(
        "UPDATE stream_digests SET digest = ? "
        "WHERE stream_id = 's' AND sequence = 3",
        (b"\xff" * 32,),
    )
    conn.commit()
    conn.close()

    compacted, watermark, tail, invalid = store.stream_integrity("s")
    assert invalid == 3
    assert (compacted, watermark) == (0, 4)
    # Tail is the last verified link (seq 2); it still recomputes cleanly.
    expected = chain_digest(
        chain_digest(ZERO_DIGEST, "s", 1, {"v": 1}), "s", 2, {"v": 2}
    )
    assert tail == expected

    # Restore the link: the full chain verifies again.
    conn = sqlite3.connect(path)
    good = chain_digest(expected, "s", 3, {"v": 3})
    conn.execute(
        "UPDATE stream_digests SET digest = ? "
        "WHERE stream_id = 's' AND sequence = 3",
        (good,),
    )
    conn.commit()
    conn.close()
    _, _, _, invalid = store.stream_integrity("s")
    assert invalid is None


def test_integrity_flags_missing_event_and_missing_link(tmp_path):
    path = str(tmp_path / "nonces.db")
    store = NonceStore(path)
    for i in range(1, 5):
        _submit(store, f"n{i}", "s", i, {"v": i})

    # Remove a stored link: a digest mismatch/missing link is reported.
    conn = sqlite3.connect(path)
    conn.execute("DELETE FROM stream_digests WHERE stream_id='s' AND sequence=2")
    conn.commit()
    conn.close()
    _, _, _, invalid = store.stream_integrity("s")
    assert invalid == 2

    # Remove an event row instead: first missing sequence is reported.
    conn = sqlite3.connect(path)
    conn.execute("DELETE FROM stream_events WHERE stream_id='s' AND sequence=2")
    conn.commit()
    conn.close()
    _, _, _, invalid = store.stream_integrity("s")
    assert invalid == 2


def test_integrity_snapshot_is_consistent_under_compaction(tmp_path):
    """Recomputation always observes one snapshot: anchor and rows agree."""
    path = str(tmp_path / "nonces.db")
    writer = NonceStore(path)
    for i in range(1, 41):
        _submit(writer, f"n{i}", "s", i, {"v": i})
    for expected in range(1, 21):
        _, claim = writer.claim_next_event("s", now=1_700_000_100)
        writer.acknowledge_lease("s", claim["token"], now=1_700_000_100)

    errors = []

    def checker():
        store = NonceStore(path)
        for _ in range(300):
            compacted, watermark, _, invalid = store.stream_integrity("s")
            if invalid is not None:
                errors.append(
                    f"invalid={invalid} compacted={compacted} wm={watermark}"
                )

    def compactor():
        store = NonceStore(path)
        for through in range(0, 21):
            store.compact_stream("s", through)

    with ThreadPoolExecutor(max_workers=4) as pool:
        futures = [pool.submit(checker) for _ in range(3)]
        futures.append(pool.submit(compactor))
        for future in futures:
            future.result()
    assert errors == []


# --- legacy database upgrade -------------------------------------------------


def _create_legacy_database(path):
    """Create a database with the pre-integrity schema and seeded state."""
    conn = sqlite3.connect(path)
    conn.executescript(
        """
        CREATE TABLE used_nonces (
            nonce TEXT PRIMARY KEY, method TEXT NOT NULL,
            path TEXT NOT NULL, seen_at INTEGER NOT NULL);
        CREATE TABLE stream_events (
            stream_id TEXT NOT NULL, sequence INTEGER NOT NULL
                CHECK (sequence >= 1),
            data_json TEXT NOT NULL, nonce TEXT NOT NULL, seen_at INTEGER NOT NULL,
            PRIMARY KEY (stream_id, sequence));
        CREATE TABLE stream_watermarks (
            stream_id TEXT PRIMARY KEY,
            high_water INTEGER NOT NULL CHECK (high_water >= 0));
        CREATE TABLE stream_consumers (
            stream_id TEXT PRIMARY KEY,
            confirmed_seq INTEGER NOT NULL CHECK (confirmed_seq >= 0));
        CREATE TABLE stream_leases (
            stream_id TEXT PRIMARY KEY,
            sequence INTEGER NOT NULL CHECK (sequence >= 1),
            token TEXT NOT NULL UNIQUE, expires_at INTEGER NOT NULL);
        CREATE TABLE stream_compactions (
            stream_id TEXT PRIMARY KEY,
            compacted_until INTEGER NOT NULL CHECK (compacted_until >= 0));
        """
    )
    return conn


def test_legacy_database_is_backfilled_from_compaction_bound(tmp_path):
    path = str(tmp_path / "legacy.db")
    conn = _create_legacy_database(path)
    # Stream s: opened through 5, 1..3 confirmed+compacted, 4 leased.
    for i in range(1, 6):
        conn.execute(
            "INSERT INTO stream_events VALUES (?,?,?,?,?)",
            ("s", i, json.dumps({"v": i}, separators=(",", ":")), f"n{i}", 1),
        )
    conn.execute("DELETE FROM stream_events WHERE stream_id='s' AND sequence<=3")
    conn.execute("INSERT INTO stream_watermarks VALUES ('s', 5)")
    conn.execute("INSERT INTO stream_consumers VALUES ('s', 3)")
    conn.execute(
        "INSERT INTO stream_leases VALUES ('s', 4, 'pending-token', 9999999999)"
    )
    conn.execute("INSERT INTO stream_compactions VALUES ('s', 3)")
    # Stream t: 3 opened, never compacted.
    for i in range(1, 4):
        conn.execute(
            "INSERT INTO stream_events VALUES (?,?,?,?,?)",
            ("t", i, json.dumps({"k": i}, separators=(",", ":")), f"m{i}", 1),
        )
    conn.execute("INSERT INTO stream_watermarks VALUES ('t', 3)")
    # Stream g: only a buffered event behind a gap: nothing to link.
    conn.execute(
        "INSERT INTO stream_events VALUES (?,?,?,?,?)",
        ("g", 5, "{}", "x", 1),
    )
    conn.execute("INSERT INTO stream_watermarks VALUES ('g', 0)")
    conn.commit()
    conn.close()

    store = NonceStore(path)  # construction runs the upgrade

    # s: an explicit zero-digest anchor row sits at the bound, followed
    # by links for the retained opened events 4 and 5.
    rows = _digest_rows(path, "s")
    assert [sequence for sequence, _ in rows] == [3, 4, 5]
    assert rows[0][1] == ZERO_DIGEST
    d4 = chain_digest(ZERO_DIGEST, "s", 4, {"v": 4})
    d5 = chain_digest(d4, "s", 5, {"v": 5})
    assert store.stream_integrity("s") == (3, 5, d5, None)

    # t: full chain from sequence 1.
    assert [s for s, _ in _digest_rows(path, "t")] == [1, 2, 3]
    e1 = chain_digest(ZERO_DIGEST, "t", 1, {"k": 1})
    e2 = chain_digest(e1, "t", 2, {"k": 2})
    e3 = chain_digest(e2, "t", 3, {"k": 3})
    assert store.stream_integrity("t") == (0, 3, e3, None)

    # g: buffered event stays unlinked.
    assert _digest_rows(path, "g") == []
    assert store.stream_integrity("g") == (0, 0, ZERO_DIGEST, None)

    # No state lost: pending lease acks, consumer cursor and bound survive.
    assert store.acknowledge_lease("s", "pending-token", now=1_700_000_100) == (
        "acknowledged", 4
    )
    assert store.compact_stream("s", 1) == ("ok", 3, 4)
    compacted, watermark, events = store.ready_events("s", after_seq=3)
    assert (compacted, watermark) == (3, 5)
    assert [event["sequence"] for event in events] == [4, 5]

    # New events chain on from the rebuilt tail; reopening is a no-op.
    store.store_stream_event(
        nonce="n6", method="POST", path="/p", now=2,
        stream_id="s", sequence=6, data={"v": 6},
    )
    reopened = NonceStore(path)
    compacted, watermark, tail, invalid = reopened.stream_integrity("s")
    assert (compacted, watermark, invalid) == (3, 6, None)
    assert tail == chain_digest(d5, "s", 6, {"v": 6})
    assert [s for s, _ in _digest_rows(path, "t")] == [1, 2, 3]


def test_legacy_upgrade_with_gap_in_retained_events_stops_chain(tmp_path):
    # A defensive case: retained rows are not contiguous up to the
    # watermark (possible only for a hand-corrupted old DB). The rebuild
    # links up to the first gap, just like ingestion would have.
    path = str(tmp_path / "legacy.db")
    conn = _create_legacy_database(path)
    for i in (1, 2, 4):
        conn.execute(
            "INSERT INTO stream_events VALUES (?,?,?,?,?)",
            ("s", i, json.dumps({"v": i}, separators=(",", ":")), f"n{i}", 1),
        )
    conn.execute("INSERT INTO stream_watermarks VALUES ('s', 4)")
    conn.commit()
    conn.close()

    store = NonceStore(path)
    assert [s for s, _ in _digest_rows(path, "s")] == [1, 2]
    compacted, watermark, tail, invalid = store.stream_integrity("s")
    assert (compacted, watermark, invalid) == (0, 4, 3)
    assert tail == chain_digest(
        chain_digest(ZERO_DIGEST, "s", 1, {"v": 1}), "s", 2, {"v": 2}
    )


# --- object-format chain migration -------------------------------------------


def _create_object_format_database(path):
    """Create a database as the pre-fix code would have left it.

    Identical schema to the current one minus the ``app_meta`` table
    (the pre-fix code recorded no format marker); digests must be added
    with :func:`_legacy_chain` so they use the object encoding.
    """
    conn = sqlite3.connect(path)
    conn.executescript(
        """
        CREATE TABLE used_nonces (
            nonce TEXT PRIMARY KEY, method TEXT NOT NULL,
            path TEXT NOT NULL, seen_at INTEGER NOT NULL);
        CREATE TABLE stream_events (
            stream_id TEXT NOT NULL, sequence INTEGER NOT NULL
                CHECK (sequence >= 1),
            data_json TEXT NOT NULL, nonce TEXT NOT NULL, seen_at INTEGER NOT NULL,
            PRIMARY KEY (stream_id, sequence));
        CREATE TABLE stream_watermarks (
            stream_id TEXT PRIMARY KEY,
            high_water INTEGER NOT NULL CHECK (high_water >= 0));
        CREATE TABLE stream_consumers (
            stream_id TEXT PRIMARY KEY,
            confirmed_seq INTEGER NOT NULL CHECK (confirmed_seq >= 0));
        CREATE TABLE stream_leases (
            stream_id TEXT PRIMARY KEY,
            sequence INTEGER NOT NULL CHECK (sequence >= 1),
            token TEXT NOT NULL UNIQUE, expires_at INTEGER NOT NULL);
        CREATE TABLE stream_compactions (
            stream_id TEXT PRIMARY KEY,
            compacted_until INTEGER NOT NULL CHECK (compacted_until >= 0));
        CREATE TABLE stream_digests (
            stream_id TEXT NOT NULL, sequence INTEGER NOT NULL
                CHECK (sequence >= 1),
            digest BLOB NOT NULL,
            PRIMARY KEY (stream_id, sequence));
        """
    )
    return conn


def _insert_event(conn, stream_id, sequence, data):
    conn.execute(
        "INSERT INTO stream_events VALUES (?,?,?,?,?)",
        (
            stream_id,
            sequence,
            json.dumps(data, ensure_ascii=False, separators=(",", ":")),
            f"n-{stream_id}-{sequence}",
            1,
        ),
    )


def _legacy_chain(conn, stream_id, sequences, previous=ZERO_DIGEST):
    """Append object-format digest rows for *sequences*; return the tail."""
    for sequence in sequences:
        (data_json,) = conn.execute(
            "SELECT data_json FROM stream_events "
            "WHERE stream_id = ? AND sequence = ?",
            (stream_id, sequence),
        ).fetchone()
        previous = legacy_chain_digest(
            previous, stream_id, sequence, json.loads(data_json)
        )
        conn.execute(
            "INSERT INTO stream_digests VALUES (?,?,?)",
            (stream_id, sequence, previous),
        )
    return previous


def _format_marker(path):
    conn = sqlite3.connect(path)
    try:
        row = conn.execute(
            "SELECT value FROM app_meta WHERE key = 'digest_format'"
        ).fetchone()
        return row[0] if row is not None else None
    finally:
        conn.close()


def test_object_format_chains_are_reencoded_at_startup(tmp_path):
    path = str(tmp_path / "v1.db")
    conn = _create_object_format_database(path)
    for i in range(1, 4):
        _insert_event(conn, "s", i, {"v": i})
    conn.execute("INSERT INTO stream_watermarks VALUES ('s', 3)")
    _legacy_chain(conn, "s", (1, 2, 3))
    conn.commit()
    # Sanity: the stored object-format links differ from the array ones.
    assert _digest_rows(path, "s")[0][1] == legacy_chain_digest(
        ZERO_DIGEST, "s", 1, {"v": 1}
    )
    conn.close()

    store = NonceStore(path)  # startup verifies, then re-encodes
    assert _format_marker(path) == DIGEST_FORMAT_ARRAY_V2

    # An uncompacted stream is recomputed from its first item.
    expected = ZERO_DIGEST
    for i in (1, 2, 3):
        expected = chain_digest(expected, "s", i, {"v": i})
    assert [digest for _, digest in _digest_rows(path, "s")] == [
        chain_digest(ZERO_DIGEST, "s", 1, {"v": 1}),
        chain_digest(
            chain_digest(ZERO_DIGEST, "s", 1, {"v": 1}), "s", 2, {"v": 2}
        ),
        expected,
    ]
    assert store.stream_integrity("s") == (0, 3, expected, None)


def test_migration_reanchors_compacted_stream_with_zero_digest(tmp_path):
    path = str(tmp_path / "v1.db")
    conn = _create_object_format_database(path)
    # Opened 1..5, confirmed 1..3, compacted through 3: the old compact
    # kept the object-format digest AT 3 as the anchor.
    for i in range(1, 6):
        _insert_event(conn, "s", i, {"v": i})
    conn.execute("INSERT INTO stream_watermarks VALUES ('s', 5)")
    conn.execute("INSERT INTO stream_consumers VALUES ('s', 3)")
    _legacy_chain(conn, "s", (1, 2, 3, 4, 5))
    conn.execute("DELETE FROM stream_events WHERE stream_id='s' AND sequence<=3")
    conn.execute("DELETE FROM stream_digests WHERE stream_id='s' AND sequence<3")
    conn.execute("INSERT INTO stream_compactions VALUES ('s', 3)")
    conn.commit()
    conn.close()

    store = NonceStore(path)

    # The deleted prefix cannot be recomputed, so the bound now carries
    # an explicit zero-digest anchor and only the retained interval
    # (3, 5] is chained from it.
    rows = _digest_rows(path, "s")
    assert [sequence for sequence, _ in rows] == [3, 4, 5]
    assert rows[0][1] == ZERO_DIGEST
    d4 = chain_digest(ZERO_DIGEST, "s", 4, {"v": 4})
    d5 = chain_digest(d4, "s", 5, {"v": 5})
    assert store.stream_integrity("s") == (3, 5, d5, None)

    # New gap fills continue from the re-anchored tail in array format.
    assert store.store_stream_event(
        nonce="n6", method="POST", path="/p", now=2,
        stream_id="s", sequence=6, data={"v": 6},
    ) == ("ok", [6], 6)
    assert store.stream_integrity("s") == (
        3, 6, chain_digest(d5, "s", 6, {"v": 6}), None,
    )


def test_migration_preserves_events_nonces_leases_and_cursors(tmp_path):
    path = str(tmp_path / "v1.db")
    conn = _create_object_format_database(path)
    for i in range(1, 6):
        _insert_event(conn, "s", i, {"v": i})
    conn.execute("INSERT INTO stream_watermarks VALUES ('s', 5)")
    conn.execute("INSERT INTO stream_consumers VALUES ('s', 3)")
    conn.execute(
        "INSERT INTO stream_leases VALUES ('s', 4, 'pending-token', 9999999999)"
    )
    conn.execute(
        "INSERT INTO used_nonces VALUES ('spent', 'POST', '/streams/events', 1)"
    )
    _legacy_chain(conn, "s", (1, 2, 3, 4, 5))
    conn.execute("DELETE FROM stream_events WHERE stream_id='s' AND sequence<=3")
    conn.execute("DELETE FROM stream_digests WHERE stream_id='s' AND sequence<3")
    conn.execute("INSERT INTO stream_compactions VALUES ('s', 3)")
    # A buffered event behind a gap on another stream must survive too.
    _insert_event(conn, "g", 9, {"v": 9})
    conn.execute("INSERT INTO stream_watermarks VALUES ('g', 0)")
    conn.commit()
    conn.close()

    store = NonceStore(path)

    # Nonce registry, lease, confirmed cursor, watermark and bound all
    # survived the migration untouched.
    assert store.register("spent", "POST", "/streams/events", 2) is False
    assert store.acknowledge_lease("s", "pending-token", now=1_700_000_100) == (
        "acknowledged", 4,
    )
    compacted, watermark, events = store.ready_events("s", after_seq=3)
    assert (compacted, watermark) == (3, 5)
    assert [event["sequence"] for event in events] == [4, 5]
    assert store.compact_stream("s", 1) == ("ok", 3, 4)
    assert store.ready_events("g", 0) == (0, 0, [])
    assert _digest_rows(path, "g") == []


def test_migration_refuses_to_rewrite_a_corrupted_chain(tmp_path):
    path = str(tmp_path / "v1.db")
    conn = _create_object_format_database(path)
    for i in range(1, 4):
        _insert_event(conn, "s", i, {"v": i})
    conn.execute("INSERT INTO stream_watermarks VALUES ('s', 3)")
    _legacy_chain(conn, "s", (1, 2, 3))
    # Corrupt one link of the legacy chain.
    conn.execute(
        "UPDATE stream_digests SET digest = ? "
        "WHERE stream_id = 's' AND sequence = 2",
        (b"\xff" * 32,),
    )
    conn.commit()
    before = _digest_rows(path, "s")
    conn.close()

    with pytest.raises(ChainCorruptionError) as excinfo:
        NonceStore(path)
    assert "'s'" in str(excinfo.value) and "sequence 2" in str(excinfo.value)

    # Nothing was silently rewritten: digests are byte-identical and no
    # format marker was committed.
    assert _digest_rows(path, "s") == before
    assert _format_marker(path) is None

    # The failure is not sticky: repair the link externally and the next
    # start migrates normally.
    conn = sqlite3.connect(path)
    fixed = legacy_chain_digest(
        legacy_chain_digest(ZERO_DIGEST, "s", 1, {"v": 1}), "s", 2, {"v": 2}
    )
    conn.execute(
        "UPDATE stream_digests SET digest = ? "
        "WHERE stream_id = 's' AND sequence = 2",
        (fixed,),
    )
    conn.commit()
    conn.close()
    store = NonceStore(path)
    assert store.stream_integrity("s")[3] is None
    assert _format_marker(path) == DIGEST_FORMAT_ARRAY_V2


def test_migration_flags_a_malformed_anchor_row(tmp_path):
    path = str(tmp_path / "v1.db")
    conn = _create_object_format_database(path)
    for i in range(1, 4):
        _insert_event(conn, "s", i, {"v": i})
    conn.execute("INSERT INTO stream_watermarks VALUES ('s', 3)")
    conn.execute("INSERT INTO stream_consumers VALUES ('s', 1)")
    _legacy_chain(conn, "s", (1, 2, 3))
    conn.execute("DELETE FROM stream_events WHERE stream_id='s' AND sequence<=1")
    conn.execute("DELETE FROM stream_digests WHERE stream_id='s' AND sequence<1")
    conn.execute("INSERT INTO stream_compactions VALUES ('s', 1)")
    # A truncated (16-byte) blob where the anchor digest should be.
    conn.execute(
        "UPDATE stream_digests SET digest = ? "
        "WHERE stream_id = 's' AND sequence = 1",
        (b"\x07" * 16,),
    )
    conn.commit()
    conn.close()

    with pytest.raises(ChainCorruptionError):
        NonceStore(path)
    assert _format_marker(path) is None


def test_migration_is_idempotent_across_restarts(tmp_path):
    path = str(tmp_path / "v1.db")
    conn = _create_object_format_database(path)
    for i in range(1, 3):
        _insert_event(conn, "s", i, {"v": i})
    conn.execute("INSERT INTO stream_watermarks VALUES ('s', 2)")
    _legacy_chain(conn, "s", (1, 2))
    conn.commit()
    conn.close()

    NonceStore(path)
    migrated_rows = _digest_rows(path, "s")
    assert _format_marker(path) == DIGEST_FORMAT_ARRAY_V2

    # A second startup is a no-op: same digests, same marker, chain
    # still verifies.
    reopened = NonceStore(path)
    assert _digest_rows(path, "s") == migrated_rows
    assert _format_marker(path) == DIGEST_FORMAT_ARRAY_V2
    assert reopened.stream_integrity("s")[3] is None


def test_unrecognised_format_marker_refuses_startup(tmp_path):
    path = str(tmp_path / "v9.db")
    NonceStore(path)  # fresh database gets the array-v2 marker
    conn = sqlite3.connect(path)
    conn.execute(
        "UPDATE app_meta SET value = 'array-v9' WHERE key = 'digest_format'"
    )
    conn.commit()
    conn.close()
    with pytest.raises(RuntimeError, match="unrecognised digest_format"):
        NonceStore(path)


# --- object-format migration: concurrency boundary ---------------------------


class _StartStoreThread(threading.Thread):
    """Thread whose target constructs a NonceStore (runs the migration)."""

    def __init__(self, path):
        super().__init__(daemon=True)
        self.path = path
        self.error = None
        self.store = None

    def run(self):
        try:
            self.store = NonceStore(self.path)
        except BaseException as exc:  # captured, asserted by the caller
            self.error = exc


def _enable_wal(path):
    """Put a legacy database into WAL mode before the migration starts.

    The migration connection otherwise performs the one-time WAL switch
    itself; doing it here lets a test hold a write lock and reliably park
    the migration *after* it requested the lock (the WAL switch never
    needs to run during the race window).
    """
    conn = sqlite3.connect(path)
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.commit()
    finally:
        conn.close()


def _adaptive_gap_fill_commit(path, stream_id, sequence, data):
    """One gap-fill commit that links in whatever encoding the database
    currently declares.

    Event row, digest and watermark advance commit in a single
    ``BEGIN IMMEDIATE`` transaction (queuing behind any migration holding
    the write lock). When the lock is acquired before the migration
    committed, there is no marker, so the object (pre-fix) encoding is
    used; once the migration has committed, the marker reads
    ``array-v2`` and the array (current) encoding is used -- exactly the
    distinction that decides whether a concurrent commit is lost by a
    stale rebuild or serialised behind the migration.
    """
    conn = sqlite3.connect(path, timeout=15.0)
    try:
        conn.execute("BEGIN IMMEDIATE")
        marker_row = conn.execute(
            "SELECT value FROM app_meta WHERE key = 'digest_format'"
        ).fetchone()
        marker = marker_row[0] if marker_row is not None else None
        conn.execute(
            "INSERT INTO stream_events VALUES (?,?,?,?,?)",
            (
                stream_id,
                sequence,
                json.dumps(data, ensure_ascii=False, separators=(",", ":")),
                f"n-{stream_id}-{sequence}",
                2,
            ),
        )
        (previous_blob,) = conn.execute(
            "SELECT digest FROM stream_digests "
            "WHERE stream_id = ? AND sequence = ?",
            (stream_id, sequence - 1),
        ).fetchone()
        link = (
            chain_digest if marker == DIGEST_FORMAT_ARRAY_V2
            else legacy_chain_digest
        )
        conn.execute(
            "INSERT INTO stream_digests VALUES (?,?,?)",
            (
                stream_id,
                sequence,
                link(bytes(previous_blob), stream_id, sequence, data),
            ),
        )
        conn.execute(
            "INSERT INTO stream_watermarks VALUES (?, ?) "
            "ON CONFLICT(stream_id) DO UPDATE SET "
            "high_water = excluded.high_water",
            (stream_id, sequence),
        )
        conn.commit()
        return marker
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def _legacy_buffered_commit_while_migration_waits(
    path, stream_id, sequence, data, *, hold_seconds=0.6
):
    """Hold the write lock, then commit one event that stays buffered
    behind a gap (no digest row, no watermark advance). The lock is held
    before the migration starts so the migration deterministically waits
    on it; when the commit lands it must be visible to the rebuild but,
    being buffered, must not produce a link.
    """
    conn = sqlite3.connect(path, timeout=30.0)
    try:
        conn.execute("BEGIN IMMEDIATE")
        time.sleep(hold_seconds)
        conn.execute(
            "INSERT INTO stream_events VALUES (?,?,?,?,?)",
            (
                stream_id,
                sequence,
                json.dumps(data, ensure_ascii=False, separators=(",", ":")),
                f"n-{stream_id}-{sequence}",
                2,
            ),
        )
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def _test_reproducing_the_race_setup(tmp_path):
    """Object-format DB (stream s open through 3) ready to be migrated."""
    path = str(tmp_path / "v1.db")
    conn = _create_object_format_database(path)
    for i in range(1, 4):
        _insert_event(conn, "s", i, {"v": i})
    conn.execute("INSERT INTO stream_watermarks VALUES ('s', 3)")
    _legacy_chain(conn, "s", (1, 2, 3))
    conn.commit()
    conn.close()
    _enable_wal(path)
    return path


def test_migration_includes_event_committed_while_waiting_for_lock(
    tmp_path, monkeypatch
):
    """The reported race: a peer opens seq 4 after the migration
    verified the old chain but before the rebuild got its write lock.

    In the old two-phase implementation the verify pass held a deferred
    read snapshot while phase 2 raced for the write lock; a peer gap
    fill committing in that window advanced the watermark past the
    snapshot the rebuild stopped at, so seq 4 ended up unlinked even
    though the array-v2 marker was written -- ``/integrity`` reported
    sequence 4 invalid. Verification now runs *inside* the write
    transaction: the peer simply queues, its commit becomes part of the
    migration's snapshot and seq 4 is rebuilt with the rest.

    The interleaving is made deterministic by slowing the first legacy
    digest computation inside the migration's verification: in the old
    implementation that computation happens on the unlocked read
    snapshot (a concurrent writer commits during the sleep); in the new
    implementation the write lock is already held and the writer waits.
    """
    import app.db as db_module

    path = _test_reproducing_the_race_setup(tmp_path)

    real_legacy_chain_digest = db_module.legacy_chain_digest

    def slow_legacy_chain_digest(previous, stream_id, sequence, data):
        if not slow_legacy_chain_digest.fired:
            slow_legacy_chain_digest.fired = True
            time.sleep(0.8)
        return real_legacy_chain_digest(previous, stream_id, sequence, data)

    slow_legacy_chain_digest.fired = False
    monkeypatch.setattr(
        db_module, "legacy_chain_digest", slow_legacy_chain_digest
    )

    peer_marker = []

    def peer():
        time.sleep(0.3)  # inside the migration's (slow) verification
        peer_marker.append(
            _adaptive_gap_fill_commit(path, "s", 4, {"v": 4})
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        peer_future = pool.submit(peer)
        migrator_future = pool.submit(NonceStore, path)
        store = migrator_future.result(15)
        peer_future.result(15)

    # Under the fixed transaction ordering the peer could not commit
    # until the migration's write transaction committed, so it observed
    # the array-v2 marker and linked seq 4 in the array encoding.
    assert peer_marker == [DIGEST_FORMAT_ARRAY_V2]
    assert _format_marker(path) == DIGEST_FORMAT_ARRAY_V2

    expected = ZERO_DIGEST
    for i in (1, 2, 3, 4):
        expected = chain_digest(expected, "s", i, {"v": i})
    assert store.stream_integrity("s") == (0, 4, expected, None)
    rows = _digest_rows(path, "s")
    assert [sequence for sequence, _ in rows] == [1, 2, 3, 4]
    assert rows[3][1] == chain_digest(
        chain_digest(
            chain_digest(
                chain_digest(ZERO_DIGEST, "s", 1, {"v": 1}),
                "s", 2, {"v": 2},
            ),
            "s", 3, {"v": 3},
        ),
        "s", 4, {"v": 4},
    )


def test_migration_serialises_a_writer_that_starts_before_it_finishes(tmp_path):
    """A writer arriving while the migration holds the write lock queues
    and observes the committed array-v2 state once it gets the lock: its
    new event chains in the array encoding and nothing is unlinked.
    """
    path = _test_reproducing_the_race_setup(tmp_path)

    def peer_writer():
        # Retry like any other store operation blocked on the lock: once
        # the migration committed, the marker is array-v2 and the gap
        # fill uses the current (array) encoding.
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            try:
                writer = NonceStore(path)
                status, opened, watermark = writer.store_stream_event(
                    nonce="n-s-4", method="POST", path="/streams/events",
                    now=2, stream_id="s", sequence=4, data={"v": 4},
                )
                assert (status, opened, watermark) == ("ok", [4], 4)
                return
            except sqlite3.OperationalError:
                time.sleep(0.01)
        raise AssertionError("peer writer never acquired the write lock")

    with ThreadPoolExecutor(max_workers=2) as pool:
        migrator_future = pool.submit(NonceStore, path)
        # Give the migration a head start at acquiring the lock.
        time.sleep(0.2)
        peer_future = pool.submit(peer_writer)
        store = migrator_future.result(15)
        peer_future.result(15)

    assert _format_marker(path) == DIGEST_FORMAT_ARRAY_V2
    expected = ZERO_DIGEST
    for i in (1, 2, 3, 4):
        expected = chain_digest(expected, "s", i, {"v": i})
    assert store.stream_integrity("s") == (0, 4, expected, None)


def test_corruption_while_migration_holds_lock_still_aborts_cleanly(tmp_path):
    """A pre-committed corruption cannot slip in between verification
    and rebuild: the commit that corrupts a chain must either be visible
    to verification (abort) or queue behind the migration. Here the bad
    link is already committed before the lock is taken, so verification
    rejects it inside the write transaction and the rollback leaves the
    original object-format database byte-identical.
    """
    path = str(tmp_path / "v1.db")
    conn = _create_object_format_database(path)
    for i in range(1, 4):
        _insert_event(conn, "s", i, {"v": i})
    conn.execute("INSERT INTO stream_watermarks VALUES ('s', 3)")
    _legacy_chain(conn, "s", (1, 2, 3))
    conn.execute(
        "UPDATE stream_digests SET digest = ? "
        "WHERE stream_id = 's' AND sequence = 2",
        (b"\xaa" * 32,),
    )
    conn.commit()
    conn.close()
    _enable_wal(path)

    before = _digest_rows(path, "s")

    migrator = _StartStoreThread(path)
    migrator.start()
    migrator.join(15)
    assert isinstance(migrator.error, ChainCorruptionError)
    assert "sequence 2" in str(migrator.error)
    assert _digest_rows(path, "s") == before
    assert _format_marker(path) is None


def test_interrupted_migration_leaves_nothing_and_retries_cleanly(
    tmp_path, monkeypatch
):
    """A crash once the rebuild has deleted and rewritten part of the
    digest table must roll back everything: no marker, original object
    digests intact, and the next startup verifies and migrates normally.
    """
    import app.db as db_module

    path = str(tmp_path / "v1.db")
    conn = _create_object_format_database(path)
    for i in range(1, 5):
        _insert_event(conn, "s", i, {"v": i})
    conn.execute("INSERT INTO stream_watermarks VALUES ('s', 4)")
    _legacy_chain(conn, "s", (1, 2, 3, 4))
    conn.commit()
    conn.close()
    _enable_wal(path)
    original = _digest_rows(path, "s")

    # Make the rebuild fail halfway: the first stream's DELETE already
    # ran inside the open write transaction when the raise fires.
    real_rebuild = db_module.NonceStore._rebuild_retained_links
    calls = {"count": 0}

    def failing_rebuild(self, conn, stream_id, compacted_until, high_water):
        real_rebuild(self, conn, stream_id, compacted_until, 2)
        calls["count"] += 1
        raise RuntimeError("simulated crash mid-migration")

    monkeypatch.setattr(
        db_module.NonceStore, "_rebuild_retained_links", failing_rebuild
    )
    with pytest.raises(RuntimeError, match="simulated crash"):
        NonceStore(path)
    assert calls["count"] == 1

    # The rollback restored the object-format digests; no marker exists,
    # so the interrupted attempt is indistinguishable from "not started".
    assert _digest_rows(path, "s") == original
    assert _format_marker(path) is None

    monkeypatch.undo()
    store = NonceStore(path)  # retried in full, succeeds
    assert _format_marker(path) == DIGEST_FORMAT_ARRAY_V2
    expected = ZERO_DIGEST
    for i in range(1, 5):
        expected = chain_digest(expected, "s", i, {"v": i})
    assert store.stream_integrity("s") == (0, 4, expected, None)


def test_two_concurrent_startups_migrate_exactly_once(tmp_path):
    """Two connections starting the migration at once serialise on the
    write lock: the loser re-reads the marker inside its own
    transaction, finds array-v2 and skips the rebuild instead of
    re-verifying chains that are already array-encoded.
    """
    path = _test_reproducing_the_race_setup(tmp_path)
    for _ in range(3):
        first = _StartStoreThread(path)
        second = _StartStoreThread(path)
        first.start()
        second.start()
        first.join(15)
        second.join(15)
        assert first.error is None and second.error is None
        assert _format_marker(path) == DIGEST_FORMAT_ARRAY_V2

    expected = ZERO_DIGEST
    for i in (1, 2, 3):
        expected = chain_digest(expected, "s", i, {"v": i})
    assert first.store.stream_integrity("s") == (0, 3, expected, None)


def test_pre_lock_commit_of_buffered_event_stays_unlinked(tmp_path):
    """A commit made while the migration waits for the lock that merely
    buffers an event behind a gap advances nothing: the rebuild follows
    the (still old) watermark and the buffered event keeps no link; once
    the gap is filled afterwards normal ingestion links it.
    """
    path = _test_reproducing_the_race_setup(tmp_path)

    peer = threading.Thread(
        target=_legacy_buffered_commit_while_migration_waits,
        args=(path, "s", 5, {"v": 5}),
    )
    peer.start()
    time.sleep(0.2)  # let the peer take the lock

    migrator = _StartStoreThread(path)
    migrator.start()
    peer.join(15)
    migrator.join(15)
    assert migrator.error is None
    store = migrator.store

    # The peer only buffered seq 5 behind the missing 4: no link for it
    # and the watermark the migration observed is still 3.
    assert [s for s, _ in _digest_rows(path, "s")] == [1, 2, 3]
    assert store.stream_integrity("s")[:2] == (0, 3)

    # Fill the gap with the current code: seq 4 opens and the walk
    # immediately picks up the pre-committed buffered seq 5.
    status, opened, watermark = store.store_stream_event(
        nonce="n-s-4", method="POST", path="/streams/events", now=3,
        stream_id="s", sequence=4, data={"v": 4},
    )
    assert (status, opened, watermark) == ("ok", [4, 5], 5)
    expected = ZERO_DIGEST
    for i in (1, 2, 3, 4, 5):
        expected = chain_digest(expected, "s", i, {"v": i})
    assert store.stream_integrity("s") == (0, 5, expected, None)


# --- HTTP endpoint -----------------------------------------------------------

SECRET = "test-secret"


def _sign(payload, secret=SECRET):
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


def _submit_event(client, stream_id, sequence, data):
    return client.post(
        "/streams/events",
        json=_event_payload(stream_id, sequence, data),
    )


def _integrity(client, stream_id):
    return client.get(f"/streams/{stream_id}/integrity")


def test_integrity_unknown_stream_returns_empty_chain(client):
    resp = _integrity(client, "ghost")
    assert resp.status_code == 200
    assert resp.json() == {
        "stream_id": "ghost",
        "compacted_until": 0,
        "watermark": 0,
        "tail_digest": "00" * 32,
        "first_invalid_sequence": None,
    }


def test_integrity_reports_chain_for_opened_events(client):
    for i in (3, 2, 1):
        _submit_event(client, "orders-42", i, {"v": i})
    # A buffered-only stream still answers with an empty chain.
    _submit_event(client, "buffered", 9, {})

    resp = _integrity(client, "orders-42")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["stream_id"] == "orders-42"
    assert (body["compacted_until"], body["watermark"]) == (0, 3)
    assert body["first_invalid_sequence"] is None
    assert len(body["tail_digest"]) == 64
    assert all(c in "0123456789abcdef" for c in body["tail_digest"])
    expected = ZERO_DIGEST
    for i in (1, 2, 3):
        expected = chain_digest(expected, "orders-42", i, {"v": i})
    assert body["tail_digest"] == expected.hex()

    buffered = _integrity(client, "buffered").json()
    assert buffered["watermark"] == 0
    assert buffered["tail_digest"] == "00" * 32


def test_integrity_follows_compaction_bound(client):
    for i in range(1, 6):
        _submit_event(client, "s", i, {"v": i})
    for _ in range(3):
        claim = client.post("/streams/s/claim")
        assert claim.status_code == 200
        ack = client.post("/streams/s/ack", json={"token": claim.json()["token"]})
        assert ack.status_code == 200
    assert client.post("/streams/s/compact", json={"through_seq": 3}).status_code == 200

    body = _integrity(client, "s").json()
    assert body["compacted_until"] == 3
    assert body["watermark"] == 5
    assert body["first_invalid_sequence"] is None

    # Append a new event: the chain continues from the retained anchor.
    before = body["tail_digest"]
    _submit_event(client, "s", 6, {"v": 6})
    after = _integrity(client, "s").json()
    assert after["watermark"] == 6
    assert after["first_invalid_sequence"] is None
    assert after["tail_digest"] != before
    assert after["tail_digest"] == chain_digest(
        bytes.fromhex(before), "s", 6, {"v": 6}
    ).hex()

