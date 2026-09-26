"""Unit tests for the atomic nonce registry and stream store."""

from app.db import LEASE_TTL_SECONDS, NonceStore

BASE_NOW = 1_700_000_000


def _submit(store, nonce, stream_id, sequence, data=None, now=1700000000):
    return store.store_stream_event(
        nonce=nonce,
        method="POST",
        path="/streams/events",
        now=now,
        stream_id=stream_id,
        sequence=sequence,
        data=data,
    )


def test_nonce_can_be_registered_only_once(tmp_path):
    store = NonceStore(str(tmp_path / "nonces.db"))
    assert store.register("n-1", "POST", "/webhook", 1700000000) is True
    assert store.register("n-1", "POST", "/webhook", 1700000001) is False


def test_distinct_nonces_are_independent(tmp_path):
    store = NonceStore(str(tmp_path / "nonces.db"))
    assert store.register("n-1", "POST", "/webhook", 1700000000) is True
    assert store.register("n-2", "POST", "/webhook", 1700000000) is True


def test_registry_survives_reopen(tmp_path):
    db = str(tmp_path / "nonces.db")
    assert NonceStore(db).register("n-1", "POST", "/webhook", 1700000000) is True
    # A fresh store over the same file still sees the consumed nonce.
    assert NonceStore(db).register("n-1", "POST", "/webhook", 1700000000) is False


def test_stream_in_order_submissions_open_one_at_a_time(tmp_path):
    store = NonceStore(str(tmp_path / "nonces.db"))
    assert _submit(store, "a", "s", 1) == ("ok", [1], 1)
    assert _submit(store, "b", "s", 2) == ("ok", [2], 2)
    compacted, watermark, events = store.ready_events("s", 0)
    assert compacted == 0
    assert watermark == 2
    assert [e["sequence"] for e in events] == [1, 2]


def test_stream_buffers_ahead_and_opens_on_gap_fill(tmp_path):
    store = NonceStore(str(tmp_path / "nonces.db"))
    assert _submit(store, "a", "s", 3, {"v": 3}) == ("ok", [], 0)
    assert _submit(store, "b", "s", 2) == ("ok", [], 0)
    assert store.ready_events("s", 0) == (0, 0, [])
    assert _submit(store, "c", "s", 1) == ("ok", [1, 2, 3], 3)
    compacted, watermark, events = store.ready_events("s", 1)
    assert compacted == 0
    assert watermark == 3
    assert [(e["sequence"], e["data"]) for e in events] == [(2, None), (3, {"v": 3})]


def test_stream_duplicate_sequence_conflicts_and_keeps_nonce(tmp_path):
    store = NonceStore(str(tmp_path / "nonces.db"))
    assert _submit(store, "a", "s", 1)[0] == "ok"
    assert _submit(store, "b", "s", 1)[0] == "duplicate_sequence"
    # The rolled-back nonce is still available for a different sequence.
    assert _submit(store, "b", "s", 2) == ("ok", [2], 2)


def test_stream_nonce_is_shared_with_register(tmp_path):
    store = NonceStore(str(tmp_path / "nonces.db"))
    assert store.register("shared", "POST", "/verify", 1700000000) is True
    assert _submit(store, "shared", "s", 1)[0] == "replayed_nonce"
    # Nothing was written for the replay.
    assert store.ready_events("s", 0) == (0, 0, [])


def test_stream_data_json_round_trip(tmp_path):
    store = NonceStore(str(tmp_path / "nonces.db"))
    payload = {"nested": [1, True, None], "msg": "你好"}
    _submit(store, "a", "s", 1, payload)
    _, _, events = store.ready_events("s", 0)
    assert events == [{"sequence": 1, "data": payload}]


def test_concurrent_gap_fill_opens_each_sequence_once(tmp_path):
    """Many connections race to fill the same gap; the watermark must
    advance in exactly one transaction and losers must be conflicts."""
    import threading
    from concurrent.futures import ThreadPoolExecutor

    db = str(tmp_path / "nonces.db")
    writer = NonceStore(db)
    for sequence in range(2, 101):
        _submit(writer, f"buf-{sequence}", "s", sequence)

    results = []
    barrier = threading.Barrier(8)

    def race(index):
        store = NonceStore(db)  # independent connection, like a worker
        barrier.wait()
        return store.store_stream_event(
            nonce=f"race-{index}",
            method="POST",
            path="/streams/events",
            now=1700000000,
            stream_id="s",
            sequence=1,
            data=None,
        )

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(race, range(8)))

    statuses = sorted(status for status, _, _ in results)
    assert statuses == ["duplicate_sequence"] * 7 + ["ok"]
    ok = next(result for result in results if result[0] == "ok")
    assert ok[1] == list(range(1, 101))
    assert ok[2] == 100

    # Conflicted transactions rolled back: their nonces are unused.
    loser_index = next(i for i, result in enumerate(results) if result[0] != "ok")
    verifier = NonceStore(db)
    assert verifier.register(f"race-{loser_index}", "POST", "/x", 1700000000) is True

    watermark, events = verifier.ready_events("s", 0)[1:]
    assert watermark == 100
    assert [event["sequence"] for event in events] == list(range(1, 101))


# --- resumable claim / ack leases --------------------------------------------


def _seed(store, stream_id, *sequences):
    for i, sequence in enumerate(sequences):
        assert _submit(
            store, f"ev-{sequence}", stream_id, sequence, {"v": sequence},
            now=BASE_NOW + i,
        )[0] == "ok"


def test_claim_empty_stream_and_beyond_watermark(tmp_path):
    store = NonceStore(str(tmp_path / "nonces.db"))
    assert store.claim_next_event("s", now=BASE_NOW) == ("empty", None)

    # seq 3 buffered behind a gap at 1: still nothing claimable.
    _seed(store, "s", 3)
    assert store.claim_next_event("s", now=BASE_NOW) == ("empty", None)


def test_claim_hands_out_next_sequence_with_token_and_expiry(tmp_path):
    store = NonceStore(str(tmp_path / "nonces.db"))
    _seed(store, "s", 1, 2)
    status, claim = store.claim_next_event("s", now=BASE_NOW)
    assert status == "claimed"
    assert claim == {
        "sequence": 1,
        "data": {"v": 1},
        "token": claim["token"],
        "expires_at": BASE_NOW + LEASE_TTL_SECONDS,
    }
    assert isinstance(claim["token"], str) and len(claim["token"]) >= 32


def test_live_lease_blocks_reclaim(tmp_path):
    store = NonceStore(str(tmp_path / "nonces.db"))
    _seed(store, "s", 1)
    status, claim = store.claim_next_event("s", now=BASE_NOW)
    assert status == "claimed"

    for delta in (0, 1, LEASE_TTL_SECONDS - 1):
        assert store.claim_next_event("s", now=BASE_NOW + delta) == ("leased", None)

    # A different stream is unaffected by the lease.
    assert _submit(store, "t-ev-1", "t", 1, {"v": 1}, now=BASE_NOW)[0] == "ok"
    other_status, other_claim = store.claim_next_event("t", now=BASE_NOW)
    assert other_status == "claimed"
    assert other_claim["sequence"] == 1


def test_expired_lease_redelivers_with_rotated_token(tmp_path):
    store = NonceStore(str(tmp_path / "nonces.db"))
    _seed(store, "s", 1, 2)
    _, first = store.claim_next_event("s", now=BASE_NOW)

    expiry = BASE_NOW + LEASE_TTL_SECONDS
    # Exactly at expiry counts as expired; a new claim wins.
    status, second = store.claim_next_event("s", now=expiry)
    assert status == "claimed"
    assert second["sequence"] == 1
    assert second["token"] != first["token"]
    assert second["expires_at"] == expiry + LEASE_TTL_SECONDS

    # The rotated token is the only valid one.
    assert store.acknowledge_lease("s", first["token"], now=expiry)[0] == (
        "invalid_token"
    )
    assert store.acknowledge_lease("s", second["token"], now=expiry) == (
        "acknowledged", 1
    )
    # After the ack seq 2 becomes claimable.
    status, claim = store.claim_next_event("s", now=expiry)
    assert status == "claimed" and claim["sequence"] == 2


def test_ack_success_advances_cursor_and_clears_lease(tmp_path):
    store = NonceStore(str(tmp_path / "nonces.db"))
    _seed(store, "s", 1)
    _, claim = store.claim_next_event("s", now=BASE_NOW)
    assert store.acknowledge_lease("s", claim["token"], now=BASE_NOW + 1) == (
        "acknowledged", 1
    )
    assert store.claim_next_event("s", now=BASE_NOW + 1) == ("empty", None)


def test_ack_failures_leave_cursor_and_lease_untouched(tmp_path):
    store = NonceStore(str(tmp_path / "nonces.db"))
    _seed(store, "s", 1)
    _, claim = store.claim_next_event("s", now=BASE_NOW)

    # Wrong token: lease stays live.
    assert store.acknowledge_lease("s", "wrong-token", now=BASE_NOW)[0] == (
        "invalid_token"
    )
    assert store.claim_next_event("s", now=BASE_NOW)[0] == "leased"

    # Expired token: rejected as lease_expired (not rotated in place).
    assert store.acknowledge_lease(
        "s", claim["token"], now=BASE_NOW + LEASE_TTL_SECONDS
    ) == ("lease_expired", None)

    # Ack with no outstanding lease.
    fresh = NonceStore(str(tmp_path / "x.db"))
    assert fresh.acknowledge_lease("s", "anything", now=BASE_NOW) == (
        "no_lease", None
    )

    # Duplicate ack after a real ack is "no lease" and cannot move cursor.
    assert store.acknowledge_lease("s", claim["token"], now=BASE_NOW) == (
        "acknowledged", 1
    )
    assert store.acknowledge_lease("s", claim["token"], now=BASE_NOW) == (
        "no_lease", None
    )
    assert store.claim_next_event("s", now=BASE_NOW)[0] == "empty"


def test_claim_does_not_cross_watermark_after_gap_fill(tmp_path):
    store = NonceStore(str(tmp_path / "nonces.db"))
    _seed(store, "s", 3)
    assert store.claim_next_event("s", now=BASE_NOW)[0] == "empty"
    _seed(store, "s", 1, 2)  # opens 1..3

    for expected in (1, 2, 3):
        status, claim = store.claim_next_event("s", now=BASE_NOW)
        assert status == "claimed" and claim["sequence"] == expected
        assert store.acknowledge_lease(
            "s", claim["token"], now=BASE_NOW
        ) == ("acknowledged", expected)

    assert store.claim_next_event("s", now=BASE_NOW)[0] == "empty"


def test_lease_persists_across_reopen(tmp_path):
    db = str(tmp_path / "nonces.db")
    store = NonceStore(db)
    _seed(store, "s", 1)
    _, claim = store.claim_next_event("s", now=BASE_NOW)

    reopened = NonceStore(db)
    # Still live after restart...
    assert reopened.claim_next_event("s", now=BASE_NOW + 1)[0] == "leased"
    # ...and the persisted token completes the ack after restart.
    assert reopened.acknowledge_lease(
        "s", claim["token"], now=BASE_NOW + 1
    ) == ("acknowledged", 1)

    again = NonceStore(db)
    assert again.claim_next_event("s", now=BASE_NOW + 1)[0] == "empty"


def test_concurrent_claims_serialise_to_one_winner(tmp_path):
    import threading
    from concurrent.futures import ThreadPoolExecutor

    db = str(tmp_path / "nonces.db")
    writer = NonceStore(db)
    _seed(writer, "s", *range(1, 21))

    results = []
    barrier = threading.Barrier(8)

    def race(_):
        store = NonceStore(db)
        barrier.wait()
        return store.claim_next_event("s", now=BASE_NOW)

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(race, range(8)))

    statuses = sorted(status for status, _ in results)
    assert statuses == ["claimed"] + ["leased"] * 7
    winners = [claim for status, claim in results if status == "claimed"]
    assert {claim["sequence"] for claim in winners} == {1}
    assert len({claim["token"] for claim in winners}) == 1


def test_concurrent_acks_serialise_to_one_success(tmp_path):
    import threading
    from concurrent.futures import ThreadPoolExecutor

    db = str(tmp_path / "nonces.db")
    writer = NonceStore(db)
    _seed(writer, "s", 1)
    token = writer.claim_next_event("s", now=BASE_NOW)[1]["token"]

    results = []
    barrier = threading.Barrier(8)

    def race(_):
        store = NonceStore(db)
        barrier.wait()
        return store.acknowledge_lease("s", token, now=BASE_NOW)[0]

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(race, range(8)))

    assert sorted(results) == ["acknowledged"] + ["no_lease"] * 7
    assert NonceStore(db).claim_next_event("s", now=BASE_NOW)[0] == "empty"


# --- prefix compaction -------------------------------------------------------


def _confirm(store, stream_id, *sequences, now=BASE_NOW):
    """Claim and acknowledge exactly *sequences* in order."""
    for expected in sequences:
        status, claim = store.claim_next_event(stream_id, now=now)
        assert status == "claimed", status
        assert claim["sequence"] == expected
        assert store.acknowledge_lease(
            stream_id, claim["token"], now=now
        ) == ("acknowledged", expected)


def test_compact_unknown_stream_only_allows_zero(tmp_path):
    store = NonceStore(str(tmp_path / "nonces.db"))
    # 0 is an idempotent no-op and persists no row / state.
    assert store.compact_stream("ghost", 0) == ("ok", 0, 0)
    assert store.ready_events("ghost", 0) == (0, 0, [])
    # Anything above the (absent) confirmed cursor is refused.
    assert store.compact_stream("ghost", 1) == ("ahead_of_confirmed", 0, 0)
    assert store.compact_stream("ghost", 5) == ("ahead_of_confirmed", 0, 0)


def test_compact_rejects_unconfirmed_prefix(tmp_path):
    store = NonceStore(str(tmp_path / "nonces.db"))
    _seed(store, "s", 1, 2, 3)
    # Nothing confirmed: even through_seq=1 is ahead of confirmed_seq=0.
    assert store.compact_stream("s", 1) == ("ahead_of_confirmed", 0, 0)

    _confirm(store, "s", 1)
    assert store.compact_stream("s", 2) == ("ahead_of_confirmed", 0, 1)
    # Refusal deletes nothing.
    assert [e["sequence"] for e in store.ready_events("s", 0)[2]] == [1, 2, 3]


def test_compact_deletes_confirmed_prefix_and_reports_bound(tmp_path):
    store = NonceStore(str(tmp_path / "nonces.db"))
    _seed(store, "s", 1, 2, 3, 4)
    _confirm(store, "s", 1, 2, 3)
    assert store.compact_stream("s", 3) == ("ok", 3, 3)

    compacted, watermark, events = store.ready_events("s", 0)
    assert (compacted, watermark) == (3, 4)
    assert events == [{"sequence": 4, "data": {"v": 4}}]
    # The confirmed cursor itself is untouched and never goes backwards.
    assert store.claim_next_event("s", now=BASE_NOW)[1]["sequence"] == 4


def test_compact_is_idempotent_and_monotonic(tmp_path):
    store = NonceStore(str(tmp_path / "nonces.db"))
    _seed(store, "s", 1, 2, 3)
    _confirm(store, "s", 1, 2)
    assert store.compact_stream("s", 2) == ("ok", 2, 2)
    # Equal and smaller requests return the persisted bound unchanged.
    assert store.compact_stream("s", 2) == ("ok", 2, 2)
    assert store.compact_stream("s", 0) == ("ok", 2, 2)
    assert store.compact_stream("s", 1) == ("ok", 2, 2)
    # Sequences below the bound stay deleted after idempotent retries.
    assert store.ready_events("s", 0)[2] == [
        {"sequence": 3, "data": {"v": 3}}
    ]


def test_compacted_sequence_is_still_duplicate_and_keeps_nonce(tmp_path):
    store = NonceStore(str(tmp_path / "nonces.db"))
    _seed(store, "s", 1, 2)
    _confirm(store, "s", 1, 2)
    assert store.compact_stream("s", 2)[0] == "ok"

    # Resubmitting a deleted, already-confirmed sequence is a conflict...
    assert _submit(store, "redo", "s", 2, {"v": 99})[0] == (
        "duplicate_sequence"
    )
    assert _submit(store, "redo", "s", 1)[0] == "duplicate_sequence"
    # ...and the rolled-back nonce is still usable for a fresh sequence.
    assert _submit(store, "redo", "s", 3, {"v": 3}) == ("ok", [3], 3)


def test_watermark_and_bound_do_not_regress_after_compact(tmp_path):
    store = NonceStore(str(tmp_path / "nonces.db"))
    _seed(store, "s", 1, 2)
    _confirm(store, "s", 1, 2)
    assert store.compact_stream("s", 2) == ("ok", 2, 2)

    # A gap-fill after compaction walks from the new floor: watermark jumps
    # forward (never back), opened only lists the newly visible sequences.
    assert _submit(store, "a", "s", 4, {"v": 4})[0] == "ok"
    assert _submit(store, "b", "s", 3, {"v": 3}) == ("ok", [3, 4], 4)

    compacted, watermark, events = store.ready_events("s", 0)
    assert (compacted, watermark) == (2, 4)
    assert [(e["sequence"], e["data"]) for e in events] == [
        (3, {"v": 3}),
        (4, {"v": 4}),
    ]


def test_compact_persists_bound_across_reopen(tmp_path):
    db = str(tmp_path / "nonces.db")
    store = NonceStore(db)
    _seed(store, "s", 1, 2, 3)
    _confirm(store, "s", 1, 2)
    store.compact_stream("s", 2)

    reopened = NonceStore(db)
    assert reopened.ready_events("s", 0) == (
        2, 3, [{"sequence": 3, "data": {"v": 3}}]
    )
    # The bound remains enforced after restart.
    assert reopened.compact_stream("s", 1) == ("ok", 2, 2)
    assert _submit(reopened, "redo", "s", 1)[0] == "duplicate_sequence"


def test_compact_does_not_remove_live_lease_beyond_bound(tmp_path):
    store = NonceStore(str(tmp_path / "nonces.db"))
    _seed(store, "s", 1, 2, 3)
    _confirm(store, "s", 1)
    # Seq 2 is currently leased (unconfirmed); compaction may only reach 1.
    _, claim = store.claim_next_event("s", now=BASE_NOW)
    assert claim["sequence"] == 2
    # Bound is still 0 at this point: no successful compaction has run.
    assert store.compact_stream("s", 2) == ("ahead_of_confirmed", 0, 1)
    assert store.compact_stream("s", 1) == ("ok", 1, 1)
    # The leased event survives the compaction and its token still acks.
    assert store.acknowledge_lease(
        "s", claim["token"], now=BASE_NOW + 1
    ) == ("acknowledged", 2)
    assert store.ready_events("s", 0)[2] == [
        {"sequence": 2, "data": {"v": 2}},
        {"sequence": 3, "data": {"v": 3}},
    ]


def test_concurrent_compact_and_writes_keep_prefix_consistent(tmp_path):
    """Writers and compactions serialise; no reader ever sees a gap."""
    from concurrent.futures import ThreadPoolExecutor

    db = str(tmp_path / "nonces.db")
    writer = NonceStore(db)
    _seed(writer, "s", *range(1, 41))
    _confirm(writer, "s", *range(1, 21))

    errors = []

    def compact_worker():
        store = NonceStore(db)
        # confirmed_seq stays at 20 during this test, so every request is
        # within the confirmed prefix and the bound ends at 20.
        for through in range(0, 21):
            status, bound, confirmed = store.compact_stream("s", through)
            if status != "ok" or not (0 <= bound <= confirmed):
                errors.append(f"bad compact result: {status}, {bound}, {confirmed}")
            # Each read is one snapshot: it must always show a contiguous
            # prefix (compacted, watermark] with no holes.
            compacted, watermark, events = store.ready_events("s", 0)
            seqs = [e["sequence"] for e in events]
            if seqs != list(range(compacted + 1, watermark + 1)):
                errors.append(f"gap in snapshot: {compacted}, {seqs}")

    def write_worker(start):
        # 41+ continue the contiguous run past the watermark, opening as
        # they land; they never disturb confirmed prefixes or compaction.
        store = NonceStore(db)
        for sequence in range(start, start + 20):
            _submit(store, f"w-{sequence}", "s", sequence, {"v": sequence})

    with ThreadPoolExecutor(max_workers=4) as pool:
        futures = [pool.submit(compact_worker) for _ in range(2)]
        futures += [pool.submit(write_worker, 41), pool.submit(write_worker, 61)]
        for future in futures:
            future.result()

    assert errors == []
    # Final bound reached exactly what was confirmed (20), never beyond.
    compacted, watermark, _ = NonceStore(db).ready_events("s", 0)
    assert compacted == 20
    # Contiguous 41..80 opened; confirmed cursor and bound stayed at 20.
    assert watermark == 80
