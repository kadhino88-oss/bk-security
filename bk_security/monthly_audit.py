"""Evidence-backed monthly activity summaries for the local V1 store.

The V1 repository applies bounded retention, so this summary deliberately
reports its coverage limits and never infers avoided attacks or remediations.
"""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
import re
from typing import Any

from .provenance import is_simulation_record

_MONTH = re.compile(r"^(\d{4})-(0[1-9]|1[0-2])$")
_EXECUTION_STATUSES = {"executed", "degraded", "failed", "rolled_back", "rollback_failed"}


def month_bounds(month: str) -> tuple[datetime, datetime]:
    match = _MONTH.fullmatch(str(month or ""))
    if not match:
        raise ValueError("month must use YYYY-MM format")
    year, selected_month = (int(value) for value in match.groups())
    try:
        start = datetime(year, selected_month, 1, tzinfo=timezone.utc)
        if selected_month == 12:
            end = datetime(year + 1, 1, 1, tzinfo=timezone.utc)
        else:
            end = datetime(year, selected_month + 1, 1, tzinfo=timezone.utc)
    except ValueError as exc:
        raise ValueError("month is outside the supported calendar range") from exc
    return start, end


def _parse_timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        result = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    if result.tzinfo is None:
        result = result.replace(tzinfo=timezone.utc)
    return result.astimezone(timezone.utc)


def _in_period(record: dict[str, Any], start: datetime, end: datetime, keys: tuple[str, ...]) -> bool:
    for key in keys:
        timestamp = _parse_timestamp(record.get(key))
        if timestamp is not None:
            return start <= timestamp < end
    return False


def _bounded_records(store: Any, method: str, requested_limit: int, attribute: str | None = None):
    limit = max(1, int(getattr(store, attribute, requested_limit))) if attribute else requested_limit
    records = getattr(store, method)(limit)
    return records, {"records_returned": len(records), "limit": limit, "may_be_truncated": len(records) >= limit}


def _counts(values: Counter) -> dict[str, int]:
    return {str(key): int(values[key]) for key in sorted(values)}


def _verified(record: dict[str, Any], key: str) -> bool:
    value = record.get(key)
    if value is True:
        return True
    nested = record.get("verification" if key == "verified" else "rollback_verification")
    return isinstance(nested, dict) and nested.get("verified") is True


def build_monthly_audit(store: Any, month: str, reliability_ledger: Any = None) -> dict[str, Any]:
    """Summarize one UTC month without returning event payloads or identifiers."""
    start, end = month_bounds(month)
    deployment_context = getattr(store, "deployment_context", None)
    scope = deployment_context.reporting_scope() if callable(
        getattr(deployment_context, "reporting_scope", None)
    ) else {
        "profile": "local_v1",
        "customer_ref": None,
        "region": None,
        "region_attestation": "not_applicable",
        "scope_enforcement": "single_local_instance",
    }
    event_limit = max(1, int(getattr(store, "max_events", 50_000)))
    alert_limit = max(1, int(getattr(store, "max_alerts", 10_000)))
    events, event_coverage = _bounded_records(store, "list_events", event_limit)
    alerts, alert_coverage = _bounded_records(store, "list_alerts", alert_limit)
    incidents, incident_coverage = _bounded_records(store, "list_incidents", 10_000)
    responses, response_coverage = _bounded_records(store, "list_response_actions", 10_000)
    audit_entries, audit_coverage = _bounded_records(store, "list_audit", 10_000)

    period_events = [item for item in events if _in_period(item, start, end, ("timestamp",))]
    simulated_events = [item for item in period_events if is_simulation_record(item)]
    event_types = Counter(str(item.get("event_type") or "unknown") for item in period_events)
    event_sources = Counter(str(item.get("source") or "unknown") for item in period_events)

    period_alerts = [item for item in alerts if _in_period(item, start, end, ("timestamp",))]
    alert_severities = Counter(str(item.get("severity") or "unknown").lower() for item in period_alerts)
    alert_types = Counter(str(item.get("alert_type") or "unknown") for item in period_alerts)

    period_incidents = [item for item in incidents if _in_period(item, start, end, ("created_at", "timestamp"))]
    incident_statuses = Counter(str(item.get("status") or "unknown").upper() for item in period_incidents)

    period_responses = [item for item in responses if _in_period(
        item, start, end, ("timestamp", "planned_at", "executed_at", "created_at")
    )]
    response_statuses = Counter(str(item.get("status") or "unknown").lower() for item in period_responses)
    response_actions = Counter(str(item.get("action") or item.get("action_type") or "unknown") for item in period_responses)
    dry_runs = [item for item in period_responses if item.get("dry_run") is True or item.get("status") == "dry_run"]
    attempted = [item for item in period_responses if item.get("execution_attempted") is True or item.get("status") in _EXECUTION_STATUSES]
    verified = [item for item in attempted if _verified(item, "verified")]
    verified_containment = [item for item in verified if item.get("action") in {"block", "isolate"}]
    verified_rollbacks = [item for item in period_responses if (
        item.get("rollback_status") == "rolled_back" and _verified(item, "rollback_verified")
    )]

    period_audit = [item for item in audit_entries if _in_period(item, start, end, ("timestamp", "ts"))]
    audit_actions = Counter(str(item.get("action") or "unknown") for item in period_audit)
    resolved_transitions = sum(
        1 for item in period_audit
        if item.get("action") == "incident_status_transition"
        and str((item.get("data") or {}).get("to", "")).upper() in {"RESOLVED", "CLOSED"}
    )

    repair_result: dict[str, Any] = {"records_in_period": None, "coverage": "not_available"}
    if reliability_ledger is not None:
        try:
            ledger_records = reliability_ledger.list_audit(1000)
            period_repairs = [item for item in ledger_records if (
                item.get("action") == "repair_succeeded"
                and _in_period(item, start, end, ("ts", "timestamp"))
            )]
            repair_result = {
                "records_in_period": len(period_repairs),
                "coverage": "bounded_recent_ledger",
                "may_be_truncated": len(ledger_records) >= 1000,
            }
        except Exception:
            repair_result = {"records_in_period": None, "coverage": "unavailable"}

    chain_status = "not_checked"
    if reliability_ledger is not None:
        try:
            valid, _diagnostic = reliability_ledger.verify_audit()
            chain_status = "valid" if valid else "invalid"
        except Exception:
            chain_status = "unavailable"

    source_coverage = {
        "events": event_coverage,
        "alerts": alert_coverage,
        "incidents": incident_coverage,
        "response_records": response_coverage,
        "operational_audit": audit_coverage,
        "safe_repair_audit": {
            "coverage": repair_result["coverage"],
            "may_be_truncated": repair_result.get("may_be_truncated", False),
        },
        "completeness": "not_proven",
        "retention_model": "bounded_local_v1_records",
    }
    possible_truncation = any(
        isinstance(value, dict) and value.get("may_be_truncated") is True
        for value in source_coverage.values()
    ) or repair_result.get("may_be_truncated") is True
    source_coverage["possible_truncation"] = possible_truncation

    return {
        "scope": scope,
        "period": {
            "month": month,
            "timezone": "UTC",
            "start_inclusive": start.isoformat(),
            "end_exclusive": end.isoformat(),
        },
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "events": {
            "records_in_period": len(period_events),
            "simulation_marked": len(simulated_events),
            "not_simulation_marked": len(period_events) - len(simulated_events),
            "by_type": _counts(event_types),
            "by_source": _counts(event_sources),
        },
        "alerts": {
            "records_in_period": len(period_alerts),
            "by_severity": _counts(alert_severities),
            "by_type": _counts(alert_types),
        },
        "incidents": {
            "created_in_period": len(period_incidents),
            "current_status_of_those_incidents": _counts(incident_statuses),
            "marked_resolved_or_closed_in_period": resolved_transitions,
        },
        "response": {
            "records_in_period": len(period_responses),
            "by_status": _counts(response_statuses),
            "by_action": _counts(response_actions),
            "dry_run_records": len(dry_runs),
            "execution_attempts": len(attempted),
            "verified_executions": len(verified),
            "unverified_execution_attempts": len(attempted) - len(verified),
            "verified_block_or_isolate_actions": len(verified_containment),
            "verified_rollbacks": len(verified_rollbacks),
            "safe_platform_repairs": repair_result,
        },
        "operational_audit": {
            "entries_in_period": len(period_audit),
            "by_action": _counts(audit_actions),
        },
        "outcomes": {
            "attacks_avoided": {"count": None, "status": "not_measured"},
            "threat_remediations": {"count": None, "status": "not_tracked_as_verified_in_v1"},
            "incident_resolutions": {"count": resolved_transitions, "status": "operator_status_transitions"},
            "reliability_audit_chain": chain_status,
        },
        "coverage": source_coverage,
        "limitations": [
            "Counts cover records retained by this local V1 instance; bounded retention may omit earlier records.",
            "Collection completeness and sensor downtime are not yet measured end to end.",
            "A verified block is not proof that an attack was avoided or that the threat was remediated.",
            "An incident marked resolved is an operator status, not independent proof of remediation.",
        ],
    }
