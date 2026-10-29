"""Versioned event envelope for authenticated collection agents (Phase 16).

The envelope carries the tenant scope claimed by the sender; it is checked
against the deployment's configured DeploymentContext and never trusted to
choose the data plane. Authenticating the agent is the caller's job.

Senders supply observations only. Identity (event_id), enrichment, risk and
correlation are server-owned and rejected if present, so an agent can neither
overwrite stored evidence nor pre-seed scores the pipeline derives.
"""
from __future__ import annotations

import json
import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, StrictInt, StrictStr, ValidationError

from ..deployment import DeploymentContext
from ..events.models import Severity

SUPPORTED_SCHEMA_VERSIONS = frozenset({1})
MAX_ENVELOPE_BYTES = 64 * 1024
MAX_CLOCK_SKEW = timedelta(minutes=5)
MAX_EVENT_AGE = timedelta(days=7)
_EVENT_NAMESPACE = uuid.uuid5(uuid.NAMESPACE_URL, "urn:bk-security:ingestion:event")
_AGENT_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
# Envelope ids must be long enough that agents do not collide by accident (counters reset, "1").
_ENVELOPE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$")

# Only sensor telemetry may arrive from agents; alerts, incidents and response
# records are produced by the server pipeline.
AgentEventType = Literal["network.connection", "network.packet", "network.dns", "endpoint.process",
                         "endpoint.socket", "endpoint.media", "lan.device"]
SERVER_OWNED_EVENT_FIELDS = frozenset({"event_id", "enrichment", "risk_score", "correlation_id"})
SERVER_OWNED_DATA_KEYS = frozenset({"indicator_score", "behavior_score", "behavior_reasons", "mitre_techniques",
                                    "related_event_ids"})


class EnvelopeError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message[:256])
        self.code = code


class _AgentEvent(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    event_type: AgentEventType
    source: StrictStr = Field(min_length=1, max_length=64)
    host_id: StrictStr = Field(min_length=1, max_length=256)
    severity: Severity = "info"
    timestamp: StrictStr | None = Field(default=None, max_length=64)
    data: dict[str, Any] = Field(default_factory=dict)
    tags: list[StrictStr] = Field(default_factory=list, max_length=64)
    process: dict[str, Any] = Field(default_factory=dict)
    network: dict[str, Any] = Field(default_factory=dict)


class _Envelope(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    schema_version: StrictInt
    envelope_id: StrictStr
    agent_id: StrictStr
    customer_ref: StrictStr
    deployment_id: StrictStr
    sequence: StrictInt = Field(ge=0)
    event: dict[str, Any]


@dataclass(frozen=True, slots=True)
class EventEnvelope:
    schema_version: int
    envelope_id: str
    agent_id: str
    sequence: int
    event: dict[str, Any]  # SecurityEvent keyword arguments, identity fixed at accept time
    content: str  # canonical JSON of the event exactly as sent, used to tell a retry from an id reuse


def _names(keys) -> str:
    listed = sorted(str(key)[:32] for key in keys)
    return ", ".join(listed[:5]) + (f" (+{len(listed) - 5})" if len(listed) > 5 else "")


def _first_error(exc: ValidationError) -> str:
    error = exc.errors()[0]
    return f"{'.'.join(str(part)[:32] for part in error.get('loc', ()))}: {error.get('type', 'invalid')}"


def _event_time(raw: str | None, received_at: datetime) -> str:
    if raw is None:
        return received_at.isoformat()
    try:
        observed = datetime.fromisoformat(raw)
    except ValueError as exc:
        raise EnvelopeError("bad_event", "event.timestamp is not ISO-8601.") from exc
    if observed.tzinfo is None:
        raise EnvelopeError("bad_event", "event.timestamp must carry a UTC offset.")
    if observed - received_at > MAX_CLOCK_SKEW or received_at - observed > MAX_EVENT_AGE:
        raise EnvelopeError("bad_timestamp", "event.timestamp is outside the accepted window.")
    return observed.astimezone(timezone.utc).isoformat()


def event_id_for(context: DeploymentContext, agent_id: str, envelope_id: str) -> str:
    """Deterministic event identity: a replay of one envelope is the same event."""
    return str(uuid.uuid5(_EVENT_NAMESPACE, f"{context.deployment_id}:{agent_id}:{envelope_id}"))


def parse_envelope(raw: bytes | str | dict, context: DeploymentContext, *,
                   received_at: datetime | None = None) -> EventEnvelope:
    """Validate raw input; raise EnvelopeError with a stable machine-readable code."""
    if context.profile != "dedicated_customer":
        raise EnvelopeError("tenant_scope_unavailable", "Remote ingestion requires a dedicated customer deployment.")
    received_at = received_at or datetime.now(timezone.utc)
    if isinstance(raw, dict):
        data = raw
    else:
        blob = raw.encode() if isinstance(raw, str) else raw
        if len(blob) > MAX_ENVELOPE_BYTES:
            raise EnvelopeError("too_large", "Envelope exceeds the size limit.")
        try:
            data = json.loads(blob)
        except (ValueError, UnicodeDecodeError, RecursionError) as exc:
            raise EnvelopeError("malformed", "Envelope is not valid JSON.") from exc
    if not isinstance(data, dict):
        raise EnvelopeError("malformed", "Envelope must be a JSON object.")
    try:
        envelope = _Envelope.model_validate(data)
    except ValidationError as exc:
        raise EnvelopeError("invalid_envelope", _first_error(exc)) from exc
    if envelope.schema_version not in SUPPORTED_SCHEMA_VERSIONS:
        raise EnvelopeError("unsupported_version", "Unsupported schema_version.")
    for value, name, pattern in ((envelope.envelope_id, "envelope_id", _ENVELOPE_ID),
                                 (envelope.agent_id, "agent_id", _AGENT_ID)):
        if not pattern.fullmatch(value):
            raise EnvelopeError("bad_identifier", f"Invalid {name}.")
    if envelope.customer_ref != context.customer_ref or envelope.deployment_id != context.deployment_id:
        raise EnvelopeError("tenant_mismatch", "Envelope tenant scope does not match this deployment.")
    owned = SERVER_OWNED_EVENT_FIELDS & set(envelope.event)
    if owned:
        raise EnvelopeError("server_owned_field", "Server-owned event fields: " + _names(owned))
    try:
        event = _AgentEvent.model_validate(envelope.event)
    except ValidationError as exc:
        raise EnvelopeError("bad_event", _first_error(exc)) from exc
    except RecursionError as exc:
        raise EnvelopeError("bad_event", "Event nesting is too deep.") from exc
    owned_keys = SERVER_OWNED_DATA_KEYS & set(event.data)
    if owned_keys:
        raise EnvelopeError("server_owned_field", "Server-owned data keys: " + _names(owned_keys))
    fields = event.model_dump()
    fields["timestamp"] = _event_time(event.timestamp, received_at)
    fields["event_id"] = event_id_for(context, envelope.agent_id, envelope.envelope_id)
    content = json.dumps(envelope.event, sort_keys=True, separators=(",", ":"), default=str)
    return EventEnvelope(envelope.schema_version, envelope.envelope_id, envelope.agent_id, envelope.sequence,
                         fields, content)
