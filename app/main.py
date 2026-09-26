"""FastAPI application: webhook signature verification and ordered streams."""

from __future__ import annotations

import os
import time
from contextlib import asynccontextmanager
from typing import Any, List, Literal, Optional

from fastapi import FastAPI, HTTPException, Query, Response
from pydantic import BaseModel, Field, field_validator

from .db import NonceStore
from .events import EventBodyError, parse_event_body
from .signing import build_canonical_string, verify_signature

# A request timestamp may differ from the server clock by this many seconds.
MAX_TIME_SKEW_SECONDS = 300


class QueryItem(BaseModel):
    """One query key/value pair; repeat items share the same key."""

    key: str = Field(..., description="Query parameter name (raw, not encoded)")
    value: str = Field(..., description="Query parameter value (raw, not encoded)")


class VerifyRequest(BaseModel):
    method: str = Field(
        ...,
        description="HTTP method of the webhook request; uppercased before signing.",
        examples=["POST"],
    )
    path: str = Field(
        ...,
        description="Request path, e.g. /webhook (used as sent).",
        examples=["/webhook"],
    )
    query: List[QueryItem] = Field(
        default_factory=list,
        description="Repeated query parameters are represented by repeated items.",
    )
    body: str = Field(
        "",
        description="Raw request body as a string; hashed as its UTF-8 bytes.",
    )
    timestamp: int = Field(
        ..., description="Unix timestamp (seconds) of the signed request."
    )
    nonce: str = Field(..., min_length=1, description="Unique single-use value.")
    signature: str = Field(
        ..., description="Lowercase hex HMAC-SHA256 signature (64 chars)."
    )


class VerifyResponse(BaseModel):
    ok: bool
    reason: Literal["verified"]
    nonce: str


class ReadyEvent(BaseModel):
    sequence: int = Field(..., description="1-based position of the event.")
    data: Any = Field(..., description="Arbitrary JSON payload as submitted.")


class ReadyResponse(BaseModel):
    stream_id: str
    watermark: int = Field(
        ..., description="Highest continuously available sequence."
    )
    events: List[ReadyEvent] = Field(
        ..., description="Ready events with sequence greater than after_seq."
    )


class IntegrityResponse(BaseModel):
    stream_id: str
    compacted_until: int = Field(
        ...,
        description=(
            "Compaction bound the recomputation started from; its retained "
            "digest is the chain anchor (32 zero bytes when the bound is 0, "
            "or when a startup migration re-anchored the chain at the bound "
            "because the compacted prefix could no longer be recomputed)."
        ),
    )
    watermark: int = Field(
        ..., description="Highest continuously available sequence."
    )
    tail_digest: str = Field(
        ...,
        description=(
            "Lowercase hex SHA-256 digest at the end of the verified chain "
            "(64 chars); 64 zero hex chars for an unknown stream or a chain "
            "that has not started."
        ),
    )
    first_invalid_sequence: Optional[int] = Field(
        ...,
        description=(
            "First sequence whose event is missing or whose stored digest "
            "does not match the recomputed chain; null when every retained "
            "opened event verifies, including for an unknown stream."
        ),
    )


class EventAcceptedResponse(BaseModel):
    ok: bool
    stream_id: str
    sequence: int
    watermark: int = Field(
        ..., description="Stream high-water mark after this submission."
    )
    opened: List[int] = Field(
        ...,
        description=(
            "Sequences that became readable due to this submission, in order; "
            "empty when the event is buffered behind a gap."
        ),
    )


class ClaimResponse(BaseModel):
    stream_id: str
    sequence: int = Field(
        ..., description="Sequence handed out; it is confirmed_seq + 1."
    )
    data: Any = Field(..., description="Arbitrary JSON payload as submitted.")
    token: str = Field(
        ...,
        description=(
            "Opaque random token required to acknowledge this lease; "
            "rotated on every (re)claim, including redelivery after expiry."
        ),
    )
    expires_at: int = Field(
        ..., description="Unix seconds after which the lease expires."
    )


class AckRequest(BaseModel):
    token: str = Field(
        ..., min_length=1, description="Token returned by POST .../claim."
    )


class AckResponse(BaseModel):
    ok: bool
    stream_id: str
    sequence: int = Field(
        ..., description="Sequence whose lease was acknowledged."
    )
    confirmed_seq: int = Field(
        ..., description="Stream's confirmed sequence after the ack."
    )


class CompactRequest(BaseModel):
    through_seq: int = Field(
        ...,
        ge=0,
        description=(
            "Delete confirmed events whose sequence is no greater than this; "
            "must not exceed the stream's confirmed_seq."
        ),
    )

    @field_validator("through_seq", mode="before")
    @classmethod
    def _must_be_real_integer(cls, value: object) -> object:
        # Runs before the int annotation coerces the value: JSON 1.0 and
        # true would otherwise be accepted silently.
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError("through_seq must be a non-negative integer")
        return value


class CompactResponse(BaseModel):
    ok: bool
    stream_id: str
    compacted_until: int = Field(
        ...,
        description=(
            "Persistent, monotonic compaction bound after this request; "
            "events with sequence <= the bound have been deleted."
        ),
    )
    confirmed_seq: int = Field(
        ..., description="Stream's confirmed sequence at compaction time."
    )


class GoneResponse(BaseModel):
    ok: bool
    error: Literal["already_compacted"]
    detail: str
    compacted_until: int = Field(
        ...,
        description=(
            "The request's after_seq lies at or below this bound; those "
            "events have been deleted. Resume reading from the bound."
        ),
    )


class ErrorResponse(BaseModel):
    ok: bool
    error: Literal[
        "invalid_signature",
        "timestamp_out_of_window",
        "replayed_nonce",
        "invalid_event_body",
        "duplicate_sequence",
        "lease_active",
        "no_active_lease",
        "invalid_token",
        "lease_expired",
        "compact_ahead_of_confirmed",
    ]
    detail: str
    compacted_until: Optional[int] = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    secret = os.environ.get("WEBHOOK_SECRET")
    if not secret:
        raise RuntimeError(
            "WEBHOOK_SECRET environment variable is required and must be non-empty"
        )
    app.state.secret = secret.encode("utf-8")
    app.state.nonce_store = NonceStore(
        os.environ.get("NONCE_DB_PATH", "data/nonces.db")
    )
    yield


app = FastAPI(
    title="Local Webhook Signature Verifier",
    version="1.5.0",
    lifespan=lifespan,
)


@app.get("/health")
async def health() -> dict:
    return {"status": "ok"}


def _error(status_code: int, error: str, detail: str) -> HTTPException:
    return HTTPException(
        status_code=status_code,
        detail={"ok": False, "error": error, "detail": detail},
    )


def _check_signed_request(secret: bytes, request: VerifyRequest) -> int:
    """Run the time-window and signature checks shared by signed endpoints.

    Failures raise before any nonce is touched, so neither a stale
    timestamp nor a bad signature can consume a nonce. Returns the
    server time used by the checks.
    """
    # 1) Timestamp window first: stale requests are rejected before any
    #    cryptographic work, and they never consume a nonce.
    now = int(time.time())
    skew = abs(now - request.timestamp)
    if skew > MAX_TIME_SKEW_SECONDS:
        raise _error(
            401,
            "timestamp_out_of_window",
            (
                f"timestamp {request.timestamp} differs from server time "
                f"{now} by {skew}s; allowed window is "
                f"±{MAX_TIME_SKEW_SECONDS}s"
            ),
        )

    # 2) Constant-time signature check. A wrong signature does not
    #    consume the nonce, so a legitimate client can retry.
    canonical = build_canonical_string(
        method=request.method.upper(),
        path=request.path,
        query_items=[(item.key, item.value) for item in request.query],
        body=request.body,
        timestamp=request.timestamp,
        nonce=request.nonce,
    )
    if not verify_signature(secret, request.signature, canonical):
        raise _error(
            401,
            "invalid_signature",
            (
                "HMAC-SHA256 signature mismatch; the signature must be "
                "the lowercase hex HMAC of the canonical string"
            ),
        )
    return now


@app.post(
    "/verify",
    response_model=VerifyResponse,
    responses={
        401: {"model": ErrorResponse, "description": "Signature or timestamp failure"},
        409: {"model": ErrorResponse, "description": "Nonce already used (replay)"},
    },
)
async def verify(request: VerifyRequest) -> VerifyResponse:
    now = _check_signed_request(app.state.secret, request)

    # 3) Atomically claim the nonce. Only a request that passed every
    #    check consumes it; a duplicate is reported as a replay.
    if not app.state.nonce_store.register(
        request.nonce, request.method.upper(), request.path, now
    ):
        raise _error(
            409,
            "replayed_nonce",
            f"nonce {request.nonce!r} has already been used",
        )

    return VerifyResponse(ok=True, reason="verified", nonce=request.nonce)


@app.post(
    "/streams/events",
    response_model=EventAcceptedResponse,
    responses={
        400: {"model": ErrorResponse, "description": "Signed body is not a valid event"},
        401: {"model": ErrorResponse, "description": "Signature or timestamp failure"},
        409: {
            "model": ErrorResponse,
            "description": "Nonce replay or duplicate sequence in the stream",
        },
    },
)
async def submit_stream_event(request: VerifyRequest) -> EventAcceptedResponse:
    """Ingest one signed, ordered event into a stream.

    The request envelope is identical to ``POST /verify``; the signed
    ``body`` string must itself be a JSON object with ``stream_id``,
    ``sequence`` (integer >= 1) and ``data`` (any JSON value).
    """
    now = _check_signed_request(app.state.secret, request)

    # Parse only after the signature is verified: the raw body string was
    # the signed artifact, and a malformed body must not consume a nonce.
    try:
        event = parse_event_body(request.body)
    except EventBodyError as exc:
        raise _error(400, "invalid_event_body", str(exc)) from exc

    # Nonce claim + event insert + watermark advance are one transaction;
    # concurrent commits cannot open the same sequences twice.
    status, opened, watermark = app.state.nonce_store.store_stream_event(
        nonce=request.nonce,
        method=request.method.upper(),
        path=request.path,
        now=now,
        stream_id=event.stream_id,
        sequence=event.sequence,
        data=event.data,
    )
    if status == "replayed_nonce":
        raise _error(
            409,
            "replayed_nonce",
            f"nonce {request.nonce!r} has already been used",
        )
    if status == "duplicate_sequence":
        raise _error(
            409,
            "duplicate_sequence",
            (
                f"stream {event.stream_id!r} already has an event with "
                f"sequence {event.sequence}"
            ),
        )

    return EventAcceptedResponse(
        ok=True,
        stream_id=event.stream_id,
        sequence=event.sequence,
        watermark=watermark,
        opened=opened,
    )


@app.get(
    "/streams/{stream_id}/ready",
    response_model=ReadyResponse,
    responses={
        410: {
            "model": GoneResponse,
            "description": (
                "after_seq is at or below the stream's compaction bound; "
                "those events have been deleted. Resume from compacted_until."
            ),
        },
    },
)
async def ready_events(
    stream_id: str,
    after_seq: int = Query(
        0,
        ge=0,
        description="Return only events whose sequence is greater than this.",
    ),
) -> ReadyResponse:
    """List events that are readable (below or at the watermark).

    Reads are non-destructive: an unknown stream or an empty window
    simply yields ``watermark: 0`` and an empty event list. When
    ``after_seq`` is at or below the stream's compaction bound the
    requested prefix no longer exists, so the response is ``410``
    carrying the current bound; resume polling with
    ``after_seq=compacted_until``.
    """
    compacted_until, watermark, events = app.state.nonce_store.ready_events(
        stream_id, after_seq
    )
    if after_seq < compacted_until:
        raise HTTPException(
            status_code=410,
            detail={
                "ok": False,
                "error": "already_compacted",
                "detail": (
                    f"stream {stream_id!r} has compacted away every sequence "
                    f"up to {compacted_until}; resume reading with "
                    f"after_seq={compacted_until}"
                ),
                "compacted_until": compacted_until,
            },
        )
    return ReadyResponse(
        stream_id=stream_id,
        watermark=watermark,
        events=[ReadyEvent(**event) for event in events],
    )


@app.get(
    "/streams/{stream_id}/integrity",
    response_model=IntegrityResponse,
)
async def stream_integrity(stream_id: str) -> IntegrityResponse:
    """Report the stream's persisted hash-chain integrity.

    The check recomputes, inside one SQLite snapshot, every retained
    opened event's SHA-256 chain link starting from the compaction
    anchor (the digest at ``compacted_until``; 32 zero bytes at the
    chain start or at a migration-re-anchored bound) and compares it
    against the stored digest. Each link hashes the previous digest's
    raw 32 bytes concatenated with the compact JSON of the
    ``[stream_id, sequence, data]`` array. The response carries the
    compaction bound, the high-water mark, the recomputed chain-tail
    digest (lowercase hex) and the first sequence that is missing or
    whose digest does not match -- ``null`` when the whole retained
    chain verifies. Verification can only cover the retained interval
    ``(compacted_until, watermark]``: a compacted-away prefix is outside
    the chain's reach. An unknown stream returns an empty chain (zero
    tail digest and no invalid sequence).
    """
    compacted_until, watermark, tail_digest, first_invalid = (
        app.state.nonce_store.stream_integrity(stream_id)
    )
    return IntegrityResponse(
        stream_id=stream_id,
        compacted_until=compacted_until,
        watermark=watermark,
        tail_digest=tail_digest.hex(),
        first_invalid_sequence=first_invalid,
    )


@app.post(
    "/streams/{stream_id}/claim",
    response_model=ClaimResponse,
    responses={
        204: {"description": "No open, unacknowledged event is available."},
        409: {
            "model": ErrorResponse,
            "description": "The next event already has an unexpired lease.",
        },
    },
)
async def claim_event(stream_id: str):
    """Claim the next unconsumed, open event of one stream under a lease.

    Only the stream's very next sequence (``confirmed_seq + 1``) is ever
    handed out, and never a sequence past the committed watermark. The
    claim carries a 30-second lease identified by a random token. While
    the lease is live a second claim conflicts with ``409``; after it
    expires the same sequence is redelivered with a *new* token. When
    there is nothing open left to consume the response is an empty
    ``204``. Claims and acks are serialised in SQLite and survive restarts.
    """
    status, claim = app.state.nonce_store.claim_next_event(stream_id)
    if status == "empty":
        # 204 No Content: no open event past the confirmed cursor.
        return Response(status_code=204)
    if status == "leased":
        raise _error(
            409,
            "lease_active",
            (
                f"stream {stream_id!r} already has an unexpired lease on "
                "the next sequence; acknowledge it or wait for the lease "
                "to expire before claiming again"
            ),
        )
    return ClaimResponse(
        stream_id=stream_id,
        sequence=claim["sequence"],
        data=claim["data"],
        token=claim["token"],
        expires_at=claim["expires_at"],
    )


@app.post(
    "/streams/{stream_id}/ack",
    response_model=AckResponse,
    responses={
        409: {
            "model": ErrorResponse,
            "description": (
                "No outstanding lease, wrong/old token, duplicate ack, or "
                "an already-expired lease; the confirmed sequence does not "
                "move."
            ),
        },
    },
)
async def acknowledge_event(stream_id: str, request: AckRequest) -> AckResponse:
    """Acknowledge a claimed event using the token from ``.../claim``.

    Only the stream's current, still-unexpired lease with the exact token
    succeeds; success atomically advances the confirmed sequence to the
    leased sequence and clears the lease. An old token, a repeated ack or
    an ack arriving after expiry is rejected with ``409`` without moving
    the confirmed cursor.
    """
    status, sequence = app.state.nonce_store.acknowledge_lease(
        stream_id, request.token
    )
    if status == "no_lease":
        raise _error(
            409,
            "no_active_lease",
            (
                f"stream {stream_id!r} has no outstanding lease; claim an "
                "event before acknowledging"
            ),
        )
    if status == "lease_expired":
        raise _error(
            409,
            "lease_expired",
            (
                "the lease for this token has expired; the event may have "
                "been redelivered to another claim, so this acknowledgement "
                "does not advance the confirmed sequence"
            ),
        )
    if status == "invalid_token":
        raise _error(
            409,
            "invalid_token",
            "the token does not match the stream's current lease token",
        )

    return AckResponse(
        ok=True,
        stream_id=stream_id,
        sequence=sequence,
        confirmed_seq=sequence,
    )


@app.post(
    "/streams/{stream_id}/compact",
    response_model=CompactResponse,
    responses={
        409: {
            "model": ErrorResponse,
            "description": (
                "through_seq is past the stream's confirmed_seq; only the "
                "confirmed prefix may be compacted and nothing is deleted."
            ),
        },
    },
)
async def compact_stream(
    stream_id: str, request: CompactRequest
) -> CompactResponse:
    """Delete a stream's already-confirmed event prefix.

    ``through_seq`` is a non-negative integer and must not exceed the
    stream's ``confirmed_seq``. The persistent bound ``compacted_until``
    only moves forward: advancing it and deleting the stream's events
    with ``sequence <= bound`` are one SQLite write transaction,
    serialised against event ingestion, claim and ack. A request at or
    below the current bound is idempotent and just reports it. An
    unknown stream (``confirmed_seq == 0``) accepts only ``0``.
    """
    status, compacted_until, confirmed_seq = (
        app.state.nonce_store.compact_stream(stream_id, request.through_seq)
    )
    if status == "ahead_of_confirmed":
        raise HTTPException(
            status_code=409,
            detail={
                "ok": False,
                "error": "compact_ahead_of_confirmed",
                "detail": (
                    f"cannot compact stream {stream_id!r} through sequence "
                    f"{request.through_seq}: only {confirmed_seq} sequence(s) "
                    "have been confirmed; acknowledge more events first"
                ),
                "compacted_until": compacted_until,
            },
        )

    return CompactResponse(
        ok=True,
        stream_id=stream_id,
        compacted_until=compacted_until,
        confirmed_seq=confirmed_seq,
    )
