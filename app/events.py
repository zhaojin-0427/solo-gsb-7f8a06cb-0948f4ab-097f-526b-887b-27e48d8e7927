"""Parsing and validation of the signed JSON event payload.

The signed ``body`` string of a ``POST /streams/events`` request must
itself be a JSON object. Parsing happens *after* the signature has been
verified (the raw string is what was signed), and a parse/validation
failure never consumes the caller's nonce.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any


class EventBodyError(ValueError):
    """Raised when the signed body is not a well-formed stream event."""


# Sequences are stored as SQLite signed 64-bit integers; reject anything
# outside that range at the boundary so we return 400 instead of 500.
MAX_SEQUENCE = 2**63 - 1


@dataclass(frozen=True)
class StreamEvent:
    """A validated event extracted from the signed body."""

    stream_id: str
    sequence: int
    data: Any


def parse_event_body(body: str) -> StreamEvent:
    """Parse a signed body string into a :class:`StreamEvent`.

    Requirements:

    * the string must be valid JSON and its top-level value must be an
      object;
    * ``stream_id`` must be present and be a non-empty string;
    * ``sequence`` must be an integer >= 1 (booleans and floats are
      rejected, even ``1.0``);
    * ``data`` must be present and may be any JSON value.
    """
    if not body:
        raise EventBodyError("signed body is empty; expected a JSON object")
    try:
        payload = json.loads(body)
    except ValueError as exc:
        raise EventBodyError(f"signed body is not valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise EventBodyError(
            f"signed body must be a JSON object, got {json_type(payload)}"
        )

    if "stream_id" not in payload:
        raise EventBodyError("missing required field 'stream_id'")
    stream_id = payload["stream_id"]
    if not isinstance(stream_id, str) or not stream_id:
        raise EventBodyError("'stream_id' must be a non-empty string")

    if "sequence" not in payload:
        raise EventBodyError("missing required field 'sequence'")
    sequence = payload["sequence"]
    # bool is a subclass of int; reject it explicitly.
    if isinstance(sequence, bool) or not isinstance(sequence, int):
        raise EventBodyError("'sequence' must be an integer")
    if sequence < 1:
        raise EventBodyError("'sequence' must be >= 1")
    if sequence > MAX_SEQUENCE:
        raise EventBodyError(f"'sequence' must be <= {MAX_SEQUENCE}")

    if "data" not in payload:
        raise EventBodyError("missing required field 'data'")

    return StreamEvent(stream_id=stream_id, sequence=sequence, data=payload["data"])


def json_type(value: Any) -> str:
    """Name of the JSON type of *value* for error messages."""
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "number"
    if isinstance(value, float):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, list):
        return "array"
    if isinstance(value, dict):
        return "object"
    return type(value).__name__
