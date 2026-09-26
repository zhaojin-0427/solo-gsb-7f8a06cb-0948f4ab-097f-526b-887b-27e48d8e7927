"""Hash-chain integrity for opened stream events.

Every event that becomes *open* (part of the contiguous prefix up to the
stream's high-water mark) is linked into a SHA-256 chain::

    digest(n) = SHA-256(
        digest(n - 1)                      # raw 32 bytes, or 32 zero bytes
        + canonical_json(event(n)).UTF-8   # for the chain's first item
    )

where ``canonical_json`` serialises exactly the **array**
``[stream_id, sequence, data]`` as compact JSON
(``separators=(",", ":")``) with the keys of every *nested* object
sorted (``sort_keys=True``); non-ASCII characters are emitted as raw
UTF-8 bytes, matching the compact representation stored at ingestion.
Digests are raw 32-byte values on the wire of this module; the API
renders them as lowercase hexadecimal.

Out-of-order events that merely sit behind a gap get no digest: the chain
is extended once, in sequence order, at the moment the gap is filled and
those sequences open. After a prefix compaction the digest *at* the
compaction bound is retained as the chain anchor, so later links continue
from it even though the anchor event itself has been deleted.

.. rubric:: Link-encoding history

The first deployed revision of this chain hashed the *object*
``{"stream_id", "sequence", "data"}`` instead of the agreed array. That
object encoding is kept here as :func:`legacy_object_event_bytes` /
:func:`legacy_chain_digest` for exactly one purpose: the startup
migration in :mod:`app.db` verifies stored legacy chains with it before
re-encoding them, and never computes anything else with it. Which
encoding a database holds is recorded in the ``app_meta`` table under
the ``digest_format`` key (see the constants below).

This module only depends on the Python standard library.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

#: Raw 32-byte "previous digest" used for the first link of every chain:
#: sequence 1 of an uncompacted stream, or the first retained sequence
#: after a compaction whose anchor was (re)set to the zero digest.
ZERO_DIGEST = b"\x00" * 32

#: Length of a SHA-256 digest in bytes.
DIGEST_LEN = 32

#: ``digest_format`` marker value written once every stored chain uses
#: the array encoding implemented by :func:`canonical_event_bytes`.
DIGEST_FORMAT_ARRAY_V2 = "array-v2"

#: ``digest_format`` marker value of chains written with the legacy
#: object encoding. Databases old enough to predate the marker simply
#: have no ``digest_format`` row, which the startup migration treats the
#: same as this value.
DIGEST_FORMAT_OBJECT_V1 = "object-v1"


def canonical_event_bytes(
    stream_id: str, sequence: int, data: Any
) -> bytes:
    """Return the canonical UTF-8 compact JSON bytes of one event.

    The payload is exactly the three-element array
    ``[stream_id, sequence, data]`` -- array order carries the field
    meaning, so no keys are serialised at the top level. Every *nested*
    object inside ``data`` has its keys sorted; there is no
    insignificant whitespace and non-ASCII characters are encoded as raw
    UTF-8.
    """
    return json.dumps(
        [stream_id, sequence, data],
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def chain_digest(
    previous: bytes, stream_id: str, sequence: int, data: Any
) -> bytes:
    """One chain step: SHA-256 over *previous* || canonical event bytes."""
    if len(previous) != DIGEST_LEN:
        raise ValueError("previous digest must be exactly 32 bytes")
    payload = previous + canonical_event_bytes(stream_id, sequence, data)
    return hashlib.sha256(payload).digest()


def legacy_object_event_bytes(
    stream_id: str, sequence: int, data: Any
) -> bytes:
    """The pre-fix link encoding: the three-key object as compact JSON.

    Retained solely so the startup migration can *verify* chains written
    before the array encoding was adopted; nothing new is ever hashed
    with it.
    """
    return json.dumps(
        {"stream_id": stream_id, "sequence": sequence, "data": data},
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def legacy_chain_digest(
    previous: bytes, stream_id: str, sequence: int, data: Any
) -> bytes:
    """One chain step over the legacy object encoding (verify only)."""
    if len(previous) != DIGEST_LEN:
        raise ValueError("previous digest must be exactly 32 bytes")
    payload = previous + legacy_object_event_bytes(stream_id, sequence, data)
    return hashlib.sha256(payload).digest()
