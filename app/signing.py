"""Canonical request serialization and HMAC-SHA256 signing.

This module only depends on the Python standard library so that the
signing logic can be tested / reused without a web framework.

Canonical string (six lines joined by ``\\n``, no trailing newline)::

    <METHOD>                 # uppercased
    <PATH>
    <CANONICAL QUERY>
    <sha256-hex of body UTF-8 bytes, lowercase>
    <UNIX TIMESTAMP>
    <NONCE>

Canonical query rules:

* every key/value is UTF-8 percent-encoded; only ASCII letters, digits and
  ``-._~`` are left unencoded (RFC 3986 unreserved set);
* the encoded ``(key, value)`` pairs are sorted lexicographically by key
  and then by value;
* duplicate keys are preserved, one ``key=value`` per occurrence;
* pairs are joined with ``&``.
"""

from __future__ import annotations

import hashlib
import hmac
import re
from typing import Iterable, Tuple

from urllib.parse import quote_from_bytes

# Lowercase hex SHA-256 digest: exactly 64 chars.
_SIGNATURE_RE = re.compile(r"^[0-9a-f]{64}$")


def percent_encode(value: str) -> str:
    """UTF-8 percent-encode *value*.

    Only ASCII letters, digits and the four characters ``-._~`` are
    left unencoded; everything else (including ``/``, ``&``, ``=`` and
    spaces) is percent-encoded using uppercase hex digits.
    """
    return quote_from_bytes(value.encode("utf-8"), safe="")


def canonical_query(items: Iterable[Tuple[str, str]]) -> str:
    """Build the canonical query string from ``(key, value)`` pairs.

    Duplicate pairs are preserved. Sorting happens after encoding, by
    encoded key first and encoded value second.
    """
    encoded: list[Tuple[str, str]] = [
        (percent_encode(key), percent_encode(value)) for key, value in items
    ]
    encoded.sort()
    return "&".join(f"{key}={value}" for key, value in encoded)


def body_digest(body: str) -> str:
    """Lowercase hex SHA-256 digest of the body's UTF-8 bytes."""
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


def build_canonical_string(
    method: str,
    path: str,
    query_items: Iterable[Tuple[str, str]],
    body: str,
    timestamp: int,
    nonce: str,
) -> str:
    """Assemble the six-line canonical string that gets signed."""
    return "\n".join(
        [
            method,
            path,
            canonical_query(query_items),
            body_digest(body),
            str(timestamp),
            nonce,
        ]
    )


def compute_signature(secret: bytes, canonical: str) -> str:
    """Return the lowercase hex HMAC-SHA256 of *canonical*."""
    return hmac.new(
        secret, canonical.encode("utf-8"), hashlib.sha256
    ).hexdigest()


def is_valid_signature_hex(signature: str) -> bool:
    """True iff *signature* is lowercase 64-char hex."""
    return _SIGNATURE_RE.fullmatch(signature) is not None


def verify_signature(
    secret: bytes, provided_signature: str, canonical: str
) -> bool:
    """Constant-time comparison of *provided_signature* against HMAC."""
    if not is_valid_signature_hex(provided_signature):
        return False
    expected = compute_signature(secret, canonical)
    return hmac.compare_digest(
        provided_signature.encode("ascii"), expected.encode("ascii")
    )
