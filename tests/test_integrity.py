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


# --- migration concurrency boundaries -----------------------------------------


def _raw_commit_open_event(path, stream_id, sequence, data, timeout=10):
    """Commit a newly opened event from a separate connection, exactly
    the way the current ingestion path does: the event row, an
    array-encoding link chained onto whatever digest is stored at the
    current watermark, and the watermark bump, in one BEGIN IMMEDIATE
    transaction."""
    conn = sqlite3.connect(path, timeout=timeout)
    conn.isolation_level = None
    try:
        conn.execute("BEGIN IMMEDIATE")
        conn.execute(
            "INSERT INTO stream_events VALUES (?,?,?,?,?)",
            (
                stream_id,
                sequence,
                json.dumps(data, ensure_ascii=False, separators=(",", ":")),
                f"raw-{stream_id}-{sequence}",
                1,
            ),
        )
        high_water = conn.execute(
            "SELECT high_water FROM stream_watermarks WHERE stream_id = ?",
            (stream_id,),
        ).fetchone()[0]
        assert sequence == high_water + 1
        anchor = conn.execute(
            "SELECT digest FROM stream_digests "
            "WHERE stream_id = ? AND sequence = ?",
            (stream_id, high_water),
        ).fetchone()
        previous = anchor[0] if anchor is not None else ZERO_DIGEST
        conn.execute(
            "INSERT INTO stream_digests VALUES (?,?,?)",
            (
                stream_id,
                sequence,
                chain_digest(previous, stream_id, sequence, data),
            ),
        )
        conn.execute(
            "UPDATE stream_watermarks SET high_water = ? WHERE stream_id = ?",
            (sequence, stream_id),
        )
        conn.commit()
    finally:
        conn.close()


def _object_db_with_chain(tmp_path, sequences=(1, 2, 3)):
    """An object-format database whose stream 's' is opened through the
    given sequences, with a matching legacy chain and no marker."""
    path = str(tmp_path / "v1.db")
    conn = _create_object_format_database(path)
    for i in sequences:
        _insert_event(conn, "s", i, {"v": i})
    conn.execute(
        "INSERT INTO stream_watermarks VALUES ('s', ?)", (max(sequences),)
    )
    _legacy_chain(conn, "s", sequences)
    conn.commit()
    conn.close()
    return path


def _expected_array_chain(stream_id, sequences):
    expected = ZERO_DIGEST
    for i in sequences:
        expected = chain_digest(expected, stream_id, i, {"v": i})
    return expected


def test_commit_before_migration_lock_is_included_in_rebuild(tmp_path):
    """Regression: an open event committed by the current ingestion code
    before the migration's write lock must be covered by the rebuild.

    The pre-fix migration verified and read the watermarks in a read-only
    transaction, then rebuilt in a separate one: a commit landing between
    the two had its fresh digest deleted by the rebuild and never
    recomputed, so /integrity reported the new sequence invalid.
    """
    path = _object_db_with_chain(tmp_path)

    # The concurrent connection commits first: its link is array-encoded
    # onto the stored object tail, exactly what the ingestion path writes
    # against a not-yet-migrated database.
    _raw_commit_open_event(path, "s", 4, {"v": 4})

    store = NonceStore(path)  # startup verifies, then re-encodes
    assert _format_marker(path) == DIGEST_FORMAT_ARRAY_V2

    # The rebuild covers the pre-migration commit: all four links are
    # chained from the zero anchor in the array encoding and verify.
    rows = _digest_rows(path, "s")
    assert [sequence for sequence, _ in rows] == [1, 2, 3, 4]
    expected = ZERO_DIGEST
    for sequence, stored in rows:
        expected = chain_digest(expected, "s", sequence, {"v": sequence})
        assert stored == expected
    assert store.stream_integrity("s") == (0, 4, expected, None)


def test_migration_holds_write_lock_from_verification_on(tmp_path, monkeypatch):
    """Regression: verification, the watermark reads and the rebuild run
    inside the migration's write transaction -- no writer can slip a
    commit between the verified snapshot and the rewrite."""
    path = _object_db_with_chain(tmp_path)

    probed = []
    original = NonceStore._verify_object_chain

    def spy(self, conn, stream_id, high_water):
        # While the migration verifies, its write lock must already be
        # held: a non-blocking writer on another connection is refused.
        probe = sqlite3.connect(path, timeout=0)
        probe.isolation_level = None
        try:
            with pytest.raises(sqlite3.OperationalError):
                probe.execute("BEGIN IMMEDIATE")
        finally:
            probe.close()
        probed.append(stream_id)
        return original(self, conn, stream_id, high_water)

    monkeypatch.setattr(NonceStore, "_verify_object_chain", spy)
    store = NonceStore(path)
    assert probed == ["s"]
    assert _format_marker(path) == DIGEST_FORMAT_ARRAY_V2
    assert store.stream_integrity("s") == (
        0, 3, _expected_array_chain("s", (1, 2, 3)), None,
    )


def test_commit_during_migration_serializes_on_the_write_lock(
    tmp_path, monkeypatch
):
    """A writer racing the migration blocks on its write lock and then
    chains onto the migrated tail; the final chain always verifies."""
    path = _object_db_with_chain(tmp_path)

    # Hold the migration's write transaction open so the racing writer
    # reliably arrives while the migration is in flight.
    rebuild_started = threading.Event()
    release_rebuild = threading.Event()
    original = NonceStore._rebuild_retained_links

    def paused(self, conn, stream_id, compacted_until, high_water):
        rebuild_started.set()
        assert release_rebuild.wait(timeout=10)
        return original(self, conn, stream_id, compacted_until, high_water)

    monkeypatch.setattr(NonceStore, "_rebuild_retained_links", paused)

    errors = []

    def migrate():
        try:
            NonceStore(path)
        except Exception as exc:  # pragma: no cover - failure reporting
            errors.append(exc)

    def write():
        try:
            assert rebuild_started.wait(timeout=10)
            _raw_commit_open_event(path, "s", 4, {"v": 4})
        except Exception as exc:  # pragma: no cover - failure reporting
            errors.append(exc)

    migrator = threading.Thread(target=migrate)
    writer = threading.Thread(target=write)
    migrator.start()
    writer.start()
    # The writer's BEGIN IMMEDIATE must still be queued on the migration's
    # write lock; it cannot commit while the migration is in flight.
    writer.join(timeout=5)
    assert writer.is_alive()
    release_rebuild.set()
    migrator.join(timeout=10)
    writer.join(timeout=10)
    assert not migrator.is_alive() and not writer.is_alive()
    assert errors == []

    store = NonceStore(path)
    assert _format_marker(path) == DIGEST_FORMAT_ARRAY_V2
    assert store.stream_integrity("s") == (
        0, 4, _expected_array_chain("s", (1, 2, 3, 4)), None,
    )


def test_concurrent_starters_migrate_exactly_once(tmp_path):
    """Two services starting against the same legacy database: one
    migrates, the other observes the committed marker inside its own
    write transaction and skips; both then chain new events onto the
    migrated tail."""
    path = _object_db_with_chain(tmp_path)

    errors = []

    def start(tag):
        try:
            store = NonceStore(path)
            status, _, _ = store.store_stream_event(
                nonce=f"post-{tag}", method="POST", path="/p", now=1,
                stream_id="s", sequence=4 + tag, data={"v": 4 + tag},
            )
            assert status == "ok"
        except Exception as exc:  # pragma: no cover - failure reporting
            errors.append(exc)

    with ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(start, range(2)))
    assert errors == []

    store = NonceStore(path)
    assert _format_marker(path) == DIGEST_FORMAT_ARRAY_V2
    assert store.stream_integrity("s") == (
        0, 5, _expected_array_chain("s", (1, 2, 3, 4, 5)), None,
    )


def test_interrupted_migration_commits_nothing_and_retries(
    tmp_path, monkeypatch
):
    """A failure inside the migration transaction rolls everything back;
    the next startup re-verifies and migrates cleanly."""
    path = _object_db_with_chain(tmp_path)
    before = _digest_rows(path, "s")

    def boom(self, conn, value):
        raise RuntimeError("simulated crash mid-migration")

    monkeypatch.setattr(NonceStore, "_write_format_marker", boom)
    with pytest.raises(RuntimeError, match="simulated crash"):
        NonceStore(path)
    # Nothing committed: digests untouched, no marker written.
    assert _digest_rows(path, "s") == before
    assert _format_marker(path) is None

    # With the fault cleared the retry migrates cleanly.
    monkeypatch.undo()
    store = NonceStore(path)
    assert _format_marker(path) == DIGEST_FORMAT_ARRAY_V2
    assert store.stream_integrity("s") == (
        0, 3, _expected_array_chain("s", (1, 2, 3)), None,
    )


def test_migration_refuses_a_tail_matching_neither_encoding(tmp_path):
    """A stored link matching neither the legacy nor the array encoding
    is corruption, not a legitimate concurrent-ingestion tail."""
    path = _object_db_with_chain(tmp_path)
    conn = sqlite3.connect(path)
    conn.execute(
        "UPDATE stream_digests SET digest = ? "
        "WHERE stream_id = 's' AND sequence = 3",
        (b"\xee" * 32,),
    )
    conn.commit()
    before = _digest_rows(path, "s")
    conn.close()

    with pytest.raises(ChainCorruptionError) as excinfo:
        NonceStore(path)
    assert "sequence 3" in str(excinfo.value)
    assert _digest_rows(path, "s") == before
    assert _format_marker(path) is None


def test_migration_refuses_object_links_after_an_array_tail(tmp_path):
    """The encoding may switch object -> array at most once (concurrent
    ingestion never writes object links); an object link following an
    array link cannot come from real ingestion and is refused."""
    path = _object_db_with_chain(tmp_path, sequences=(1,))
    conn = sqlite3.connect(path)
    for i in (2, 3):
        _insert_event(conn, "s", i, {"v": i})
    conn.execute("UPDATE stream_watermarks SET high_water = 3")
    # Link 2: array encoding onto the object tail (legitimate concurrent
    # ingestion); link 3: object encoding again (impossible in practice).
    object_tail = conn.execute(
        "SELECT digest FROM stream_digests WHERE stream_id='s' AND sequence=1"
    ).fetchone()[0]
    array_link = chain_digest(object_tail, "s", 2, {"v": 2})
    conn.execute(
        "INSERT INTO stream_digests VALUES (?,?,?)", ("s", 2, array_link)
    )
    conn.execute(
        "INSERT INTO stream_digests VALUES (?,?,?)",
        ("s", 3, legacy_chain_digest(array_link, "s", 3, {"v": 3})),
    )
    conn.commit()
    conn.close()

    with pytest.raises(ChainCorruptionError) as excinfo:
        NonceStore(path)
    assert "sequence 3" in str(excinfo.value)
    assert _format_marker(path) is None


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

