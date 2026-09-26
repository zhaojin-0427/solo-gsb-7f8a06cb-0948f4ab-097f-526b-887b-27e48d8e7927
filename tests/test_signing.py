"""Unit tests for the canonicalization / signing helpers."""

import hashlib
import hmac

from app.signing import (
    build_canonical_string,
    canonical_query,
    compute_signature,
    is_valid_signature_hex,
    percent_encode,
    verify_signature,
)


def test_percent_encode_unreserved_set():
    assert percent_encode("abcXYZ019-._~") == "abcXYZ019-._~"


def test_percent_encode_encodes_everything_else():
    assert percent_encode("a b&c=d/e") == "a%20b%26c%3Dd%2Fe"
    assert percent_encode("café") == "caf%C3%A9"  # UTF-8, uppercase hex


def test_canonical_query_sorts_by_key_then_value_and_keeps_duplicates():
    items = [("b", "2"), ("a", "1"), ("a", "0"), ("b", "10")]
    assert canonical_query(items) == "a=0&a=1&b=10&b=2"


def test_canonical_query_encodes_before_sorting():
    items = [("sp ace", "a&b"), ("a", "1")]
    assert canonical_query(items) == "a=1&sp%20ace=a%26b"


def test_canonical_query_empty():
    assert canonical_query([]) == ""


def test_build_canonical_string_layout():
    body = "hello"
    expected_digest = hashlib.sha256(body.encode("utf-8")).hexdigest()
    canonical = build_canonical_string(
        method="POST",
        path="/webhook",
        query_items=[("a", "1")],
        body=body,
        timestamp=1700000000,
        nonce="n-1",
    )
    assert canonical == (
        f"POST\n/webhook\na=1\n{expected_digest}\n1700000000\nn-1"
    )


def test_signature_matches_independent_hmac():
    canonical = "POST\n/webhook\na=1\n" + "x" * 64 + "\n1700000000\nn-1"
    expected = hmac.new(b"secret", canonical.encode(), hashlib.sha256).hexdigest()
    assert compute_signature(b"secret", canonical) == expected
    assert verify_signature(b"secret", expected, canonical)
    assert not verify_signature(b"wrong", expected, canonical)


def test_verify_signature_rejects_malformed_hex():
    canonical = "anything"
    assert not is_valid_signature_hex("zz" * 32)
    assert not is_valid_signature_hex("A" * 64)  # uppercase not allowed
    assert not is_valid_signature_hex("a" * 63)
    assert not verify_signature(b"s", "not-hex", canonical)
