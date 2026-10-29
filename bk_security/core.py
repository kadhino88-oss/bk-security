from __future__ import annotations
import os
from .detection.rules import DetectionEngine
from .detection.behavior import BehaviorEngine
from .detection.correlation import CorrelationEngine
from .events.bus import SecurityEventBus
from .events.models import SecurityAlert, SecurityEvent
from .events.sanitization import sanitize_security_event
from .detection.risk import RiskEngine
from .policy.engine import Action, ResponsePolicy
from .policy.response import ResponseEngine
from .policy.windows_adapters import build_windows_adapters
from .incidents import SecurityIncident
from .incidents.lifecycle import INCIDENT_STATUSES, normalize_incident_status, transition_incident
from .intelligence import ThreatIntelEngine
from .detection.mitre import techniques_for_event
from .ai.orchestrator import SecurityOrchestrator
from .ai.workers.builtin import ThreatAnalyst, NetworkAnalyst, ProcessAnalyst, BehaviorAnalyst, IncidentAnalyst, ThreatIntelAnalyst, ForensicsAnalyst, SecurityReporter
from .database import SecurityRepository, SecurityStore
from .provenance import is_simulation_record
from .autonomy import AutonomyController
from collections import OrderedDict, defaultdict
from datetime import datetime, timezone
import threading
import hashlib
from uuid import uuid4

def _response_adapters() -> dict:
    """Response adapters are off unless explicitly enabled; the platform layer picks them per OS."""
    if os.name == 'nt' and os.getenv('BK_SECURITY_WINDOWS_RESPONSE', '0') == '1':
        return build_windows_adapters()
    if os.getenv('BK_SECURITY_OS_RESPONSE', '0') == '1':
        from .platforms import current_provider
        return current_provider().response_adapters()
    return {}


class SecurityCore:
    """BK Security decision core: normalize -> behavior -> detect -> correlate -> incident."""
    def __init__(self, store: SecurityRepository | None = None) -> None:
        self.store: SecurityRepository = store if store is not None else SecurityStore()
        self.bus = SecurityEventBus(); self.risk = RiskEngine()
        self.behavior = BehaviorEngine(); self.detector = DetectionEngine(self.risk)
        self.correlation = CorrelationEngine(); self.policy = ResponsePolicy(); self.response = ResponseEngine(adapters=_response_adapters())
        self.threat_intel = ThreatIntelEngine()
        self.ai = SecurityOrchestrator([ThreatAnalyst(), NetworkAnalyst(), ProcessAnalyst(), BehaviorAnalyst(), IncidentAnalyst(), ThreatIntelAnalyst(), ForensicsAnalyst(), SecurityReporter()])
        self.response.restore(self.store.list_response_actions(500))
        for execution_id, recovered in self.response.executions.items():
            if recovered.get("recovered_incomplete_execution"):
                self.store.save_response_action(recovered)
                self.store.audit("system", "response_execution_recovered", recovered.get("target"), {
                    "plan_id": recovered.get("plan_id"), "execution_id": execution_id,
                    "action": recovered.get("action"), "status": recovered.get("status"),
                    "reason": recovered.get("reason"), "evidence_ids": recovered.get("evidence_ids", []),
                    "verification": recovered.get("verification"),
                })
        self._state_lock = threading.RLock()
        self.autonomy = AutonomyController(self)
        restored_events = self._restore_records(self.store.list_events(5000), SecurityEvent)[-5000:]
        restored_alerts = self._restore_records(self.store.list_alerts(5000), SecurityAlert)[-5000:]
        # The repository exposes incidents newest-first for the SOC API. Keep
        # the core's in-memory history chronological, matching events/alerts.
        incident_records = self.store.list_incidents(10_000)
        restored_incidents = self._restore_records(reversed(incident_records), SecurityIncident)[-5000:]
        self.simulation_excluded_records = {"events": 0, "alerts": 0, "incidents": 0}
        if os.getenv("BK_SECURITY_ENV", "").strip().lower() == "production":
            simulated_event_ids = {
                event.event_id for event in restored_events if is_simulation_record(event)
            }
            # Alerts can outlive the bounded in-memory event window. Resolve only
            # their cited evidence IDs so old simulations remain separated.
            for alert in restored_alerts:
                for event_id in alert.source_event_ids:
                    if event_id in simulated_event_ids:
                        continue
                    source_event = self.store.get_event(event_id)
                    if source_event is not None and is_simulation_record(source_event):
                        simulated_event_ids.add(event_id)

            simulated_alert_ids = {
                alert.alert_id for alert in restored_alerts
                if alert.source_event_ids and set(alert.source_event_ids) <= simulated_event_ids
            }
            simulated_incident_ids = {
                incident.incident_id for incident in restored_incidents
                if incident.alert_ids and set(incident.alert_ids) <= simulated_alert_ids
            }
            self.simulation_excluded_records = {
                "events": len(simulated_event_ids),
                "alerts": len(simulated_alert_ids),
                "incidents": len(simulated_incident_ids),
            }
            self.events = [event for event in restored_events if event.event_id not in simulated_event_ids]
            self.alerts = [alert for alert in restored_alerts if alert.alert_id not in simulated_alert_ids]
            self.incidents = [incident for incident in restored_incidents if incident.incident_id not in simulated_incident_ids]
        else:
            self.events = restored_events
            self.alerts = restored_alerts
            self.incidents = restored_incidents
        active_incident_ids: set[str] = set()
        for incident in self.incidents:
            try:
                normalized = normalize_incident_status(incident.status)
            except ValueError:
                continue
            if normalized != incident.status:
                incident.status = normalized
                self.store.save_incident(incident)
            if normalized not in {"RESOLVED", "CLOSED"}:
                active_incident_ids.add(incident.incident_id)
        self._incident_index: dict[str, SecurityIncident] = {
            incident.incident_id: incident for incident in self.incidents
            if incident.incident_id in active_incident_ids
        }
        # Correlation clusters use transient keys for new incidents and durable
        # incident IDs after restore. Keep the mapping explicit so a cluster can
        # never accidentally collapse unrelated incidents.
        self._correlation_incidents: dict[str, str] = {
            incident_id: incident_id for incident_id in active_incident_ids
        }
        self._incident_correlation_keys: defaultdict[str, set[str]] = defaultdict(set)
        for incident_id in active_incident_ids:
            self._incident_correlation_keys[incident_id].add(incident_id)

        # Low/info telemetry can be extremely repetitive on a live network.
        # Deduplicate only low-value alerts; medium/high/critical alerts remain
        # independently observable and are still correlated into incidents.
        self._alert_dedup_window_seconds = 300
        self._alert_dedup: OrderedDict[str, tuple[str, float]] = OrderedDict()
        for alert in self.alerts:
            if alert.severity in {"info", "low"}:
                self._alert_dedup[self._alert_fingerprint(alert)] = (
                    alert.alert_id, self._event_epoch(alert.timestamp)
                )
        while len(self._alert_dedup) > 5000:
            self._alert_dedup.popitem(last=False)

        self.correlation.restore(self.alerts, active_incident_ids)
        self._dns_context: OrderedDict[str, dict[str, tuple[str, float, str]]] = OrderedDict()
        for event in self.events:
            if event.event_type == "network.dns":
                self._remember_dns(event, self._event_epoch(event.timestamp))
        self.bus.subscribe("*", self._on_event)
        trim_retention = getattr(self.store, "trim_retention", None)
        if callable(trim_retention):
            trim_retention()

    @staticmethod
    def _restore_records(records, model):
        restored = []
        for record in records:
            try:
                restored.append(model(**record))
            except (TypeError, ValueError):
                continue
        return restored

    @staticmethod
    def _event_epoch(timestamp: str) -> float:
        try:
            parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed.timestamp()
        except (AttributeError, TypeError, ValueError, OverflowError):
            return datetime.now(timezone.utc).timestamp()

    @staticmethod
    def _alert_fingerprint(alert: SecurityAlert) -> str:
        """Fingerprint the security condition, not an individual packet."""
        evidence: dict[str, str] = {}
        for item in alert.evidence:
            field_name = str(item.get("field") or "").strip().lower()
            value = item.get("value")
            if value is None or value == "":
                continue
            if field_name in {
                "process", "destination_port", "destination_domain", "anomaly"
            }:
                evidence[field_name] = str(value).strip().lower()

        # For info/low network behavior, destination IP is intentionally not
        # part of the fingerprint: a stream of first-seen destinations is one
        # behavioral condition, not one incident per destination.
        payload = "|".join([
            str(alert.host_id).strip().lower(),
            str(alert.alert_type).strip().upper(),
            evidence.get("process", ""),
            evidence.get("destination_port", ""),
            evidence.get("destination_domain", ""),
            evidence.get("anomaly", ""),
            ",".join(sorted(str(x).upper() for x in alert.mitre_techniques if x)),
        ])
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def _deduplicate_low_alert(
        self, alert: SecurityAlert, now: float
    ) -> SecurityAlert | None:
        if alert.severity not in {"info", "low"}:
            return None

        fingerprint = self._alert_fingerprint(alert)
        previous = self._alert_dedup.get(fingerprint)
        if previous is None:
            self._alert_dedup[fingerprint] = (alert.alert_id, now)
            self._alert_dedup.move_to_end(fingerprint)
            return None

        alert_id, seen = previous
        if now - seen > self._alert_dedup_window_seconds:
            self._alert_dedup[fingerprint] = (alert.alert_id, now)
            self._alert_dedup.move_to_end(fingerprint)
            return None

        existing = next((item for item in self.alerts if item.alert_id == alert_id), None)
        if existing is None:
            self._alert_dedup[fingerprint] = (alert.alert_id, now)
            self._alert_dedup.move_to_end(fingerprint)
            return None

        # Merge evidence/source-event references without manufacturing a new
        # alert. Keep the strongest observed risk and latest timestamp.
        existing.source_event_ids = list(dict.fromkeys(
            [*existing.source_event_ids, *alert.source_event_ids]
        ))[-64:]
        existing.evidence = list(existing.evidence)
        for item in alert.evidence:
            if item not in existing.evidence and len(existing.evidence) < 64:
                existing.evidence.append(item)
        existing.risk_score = max(existing.risk_score, alert.risk_score)
        existing.confidence = max(existing.confidence, alert.confidence)
        existing.timestamp = alert.timestamp

        self._alert_dedup[fingerprint] = (existing.alert_id, now)
        self._alert_dedup.move_to_end(fingerprint)
        return existing

    def _remember_dns(self, event: SecurityEvent, event_epoch: float) -> None:
        domain = str(event.data.get("domain") or "").strip().lower().rstrip(".")
        if not domain:
            return
        host_dns = self._dns_context.setdefault(event.host_id, {})
        self._dns_context.move_to_end(event.host_id)
        while len(self._dns_context) > 256:
            self._dns_context.popitem(last=False)
        for answer in event.data.get("answers") or []:
            address = str(answer).strip()
            if address:
                host_dns[address] = (domain, event_epoch, event.event_id)
        stale = [address for address, (_, seen, _) in host_dns.items() if event_epoch - seen > 3600]
        for address in stale:
            host_dns.pop(address, None)
        if len(host_dns) > 1024:
            oldest = sorted(host_dns.items(), key=lambda item: item[1][1])
            for address, _ in oldest[:len(host_dns) - 1024]:
                host_dns.pop(address, None)

    def ingest(self, event: SecurityEvent) -> list[SecurityAlert]:
        with self._state_lock:
            before = len(self.alerts)
            self.bus.publish(event)
            return self.alerts[before:]

    def plan_response(self, action, target: str, reason: str, *, actor: str, actor_role: str,
                      dry_run: bool = True, risk_level: str = "high",
                      risk_score: int | None = None, alert_id: str | None = None,
                      incident_id: str | None = None, evidence_ids: list[str] | None = None,
                      ai_recommendation=None, plan_id: str | None = None) -> dict:
        """Resolve trusted context and persist a policy decision and response plan."""
        if actor_role not in {"admin", "analyst"}:
            raise PermissionError("Only admin or analyst roles can prepare a response plan.")
        with self._state_lock:
            alert = next((item for item in self.alerts if item.alert_id == alert_id), None) if alert_id else None
            if alert_id and alert is None:
                raise LookupError("Alert not found.")
            incident = next((item for item in self.incidents if item.incident_id == incident_id), None) if incident_id else None
            if incident_id and incident is None:
                raise LookupError("Incident not found.")
            if alert is not None:
                risk_level = alert.severity
                risk_score = alert.risk_score
            elif incident is not None:
                risk_level = incident.severity
                risk_score = incident.risk_score
            known_evidence = {item.event_id for item in self.events}
            known_evidence.update(item.alert_id for item in self.alerts)
            known_evidence.update(item.incident_id for item in self.incidents)
            if alert is not None:
                known_evidence.update(alert.source_event_ids)
            if incident is not None:
                known_evidence.update(incident.alert_ids)
            evidence_ids = list(dict.fromkeys(evidence_ids or []))
            if any(item not in known_evidence for item in evidence_ids):
                raise LookupError("Evidence reference not found.")
            if alert is not None and evidence_ids and not set(evidence_ids).issubset(
                {alert.alert_id, *alert.source_event_ids}
            ):
                raise ValueError("Evidence references do not belong to the linked alert.")
            if incident is not None and evidence_ids and not set(evidence_ids).issubset(
                {incident.incident_id, *incident.alert_ids}
            ):
                raise ValueError("Evidence references do not belong to the linked incident.")
            risk_score = risk_score if risk_score is not None else {
                "critical": 100, "high": 80, "medium": 55, "low": 25, "info": 5,
            }.get(str(risk_level).lower(), 0)
            decision = self.policy.evaluate(
                risk_level, requested_action=action, ai_recommendation=ai_recommendation
            )
            resolved_plan_id = plan_id or str(uuid4())
            plan = self.response.plan(
                resolved_plan_id, Action(decision["action"]), target, reason,
                dry_run=dry_run, risk_level=risk_level, risk_score=risk_score,
                alert_id=alert_id, incident_id=incident_id, evidence_ids=evidence_ids,
                policy_decision=decision,
                ai_recommendation=decision["ai_recommendation"],
            )
            self.store.save_response_action(plan)
            self.store.audit(actor, "response_policy_decision", target, {
                "plan_id": resolved_plan_id, **decision, "alert_id": alert_id,
                "incident_id": incident_id, "evidence_ids": evidence_ids,
            })
            self.store.audit(actor, "response_plan", target, plan)
            return plan

    def approve_response(self, plan_id: str, *, actor: str, role: str,
                         rollback: bool = False) -> dict:
        with self._state_lock:
            context = self.response.executions.get(plan_id) if rollback else self.response.plans.get(plan_id)
            if context is None:
                context = self.response.plans.get(plan_id)
            result = self.response.approve(plan_id, actor, role, rollback=rollback)
            if not rollback:
                self.store.save_response_action(result)
            else:
                self.store.save_response_action(self.response.executions[plan_id])
            self.store.audit(actor, "response_rollback_approval" if rollback else "response_approval",
                             (context or {}).get("target") or plan_id, {
                                 "plan_id": plan_id, "action": (context or {}).get("action"),
                                 "result": "approved", "reason": (context or {}).get("reason"),
                                 "evidence_ids": (context or {}).get("evidence_ids", []),
                                 "approval": result.get("rollback_approval" if rollback else "approval"),
                             })
            return result

    def execute_response(self, execution_id: str, plan_id: str, *, actor: str, actor_role: str,
                         dry_run: bool | None = None) -> dict:
        """Execute a persisted plan using actor-bound approval and verification."""
        if actor_role != "responder":
            raise PermissionError("Only the responder role can execute a response.")
        with self._state_lock:
            plan = self.response.plans.get(plan_id, {})
            started = {
                **plan, "plan_id": plan_id, "execution_id": execution_id,
                "execution_actor": actor, "execution_started_at": datetime.now(timezone.utc).isoformat(),
                "status": "executing", "executed": False,
            }
            self.store.save_response_action(started)
            self.store.audit(actor, "response_execution_started", plan.get("target"), {
                "plan_id": plan_id, "execution_id": execution_id, "action": plan.get("action"),
                "reason": plan.get("reason"), "evidence_ids": plan.get("evidence_ids", []),
            })
            result = self.response.execute(execution_id, plan_id, actor, actor_role, dry_run=dry_run)
            self.store.save_response_action(result)
            self.store.audit(actor, "response_execute", result.get("target"), {
                "plan_id": plan_id, "execution_id": execution_id, "action": result.get("action"),
                "status": result.get("status"), "reason": result.get("reason"),
                "alert_id": result.get("alert_id"), "incident_id": result.get("incident_id"),
                "evidence_ids": result.get("evidence_ids", []),
            })
            if "verification" in result:
                self.store.audit(actor, "response_verification", result.get("target"), {
                    "plan_id": plan_id, "execution_id": execution_id,
                    "status": result.get("status"), "verification": result["verification"],
                    "evidence_ids": result.get("evidence_ids", []),
                })
            return result

    def rollback_response(self, execution_id: str, *, actor: str, actor_role: str) -> dict:
        """Attempt rollback and persist the updated execution record when present."""
        if actor_role != "responder":
            raise PermissionError("Only the responder role can roll back a response.")
        with self._state_lock:
            context = self.response.executions.get(execution_id, {})
            result = self.response.rollback(execution_id, actor, actor_role)
            execution = self.response.executions.get(execution_id)
            if execution:
                self.store.save_response_action(execution)
            self.store.audit(actor, "response_rollback", context.get("target") or execution_id, {
                **result, "action": context.get("action"), "reason": context.get("reason"),
                "evidence_ids": context.get("evidence_ids", []),
            })
            return result

    def transition_incident(self, incident_id: str, status: str, actor: str) -> dict:
        with self._state_lock:
            incident = next((item for item in self.incidents if item.incident_id == incident_id), None)
            if incident is None:
                raise LookupError("Incident not found")
            old_status = incident.status
            old_updated = incident.updated_at
            previous, target = transition_incident(incident, status)
            try:
                self.store.record_incident_transition(incident, actor, previous, target)
            except Exception:
                incident.status = old_status
                incident.updated_at = old_updated
                raise

            if target in {"RESOLVED", "CLOSED"}:
                for key in self._incident_correlation_keys.pop(incident_id, set()):
                    self._correlation_incidents.pop(key, None)
                    self.correlation.discard_incident(key)
                self.correlation.discard_incident(incident_id)
                self._incident_index.pop(incident_id, None)
            else:
                self._incident_index[incident_id] = incident
                self._correlation_incidents[incident_id] = incident_id
                self._incident_correlation_keys[incident_id].add(incident_id)
                self.correlation.restore(self.alerts, {incident_id})
            return incident.to_dict()

    @staticmethod
    def _threat_fingerprint(alert: SecurityAlert) -> tuple[str, str]:
        """Return a stable identity for a recurring threat.

        PID, timestamp and severity are deliberately excluded. Separate
        incidents can therefore belong to the same recurring threat family.
        """
        process_names: set[str] = set()
        destinations: set[str] = set()
        ports: set[str] = set()

        for item in alert.evidence:
            field_name = str(item.get("field") or "").strip().lower()
            value = item.get("value")

            if value is None or value == "":
                continue

            normalized = str(value).strip().lower()

            if field_name == "process":
                process_names.add(normalized)
            elif field_name in {"destination_ip", "destination_domain"}:
                destinations.add(normalized)
            elif field_name == "destination_port":
                ports.add(normalized)

        payload = "|".join([
            f"host={str(alert.host_id).strip().lower()}",
            f"type={str(alert.alert_type).strip().upper()}",
            f"process={','.join(sorted(process_names))}",
            f"destination={','.join(sorted(destinations))}",
            f"port={','.join(sorted(ports))}",
            f"mitre={','.join(sorted(str(x).strip().upper() for x in alert.mitre_techniques if x))}",
        ])

        digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        return f"tf-{digest[:20]}", digest

    def _attach_threat_family(
        self,
        incident: SecurityIncident,
        alert: SecurityAlert,
    ) -> None:
        family_id, fingerprint = self._threat_fingerprint(alert)
        incident.threat_family_id = family_id
        incident.threat_fingerprint = fingerprint

    def _on_event(self, event: SecurityEvent) -> None:
        sanitize_security_event(event)
        self.events.append(event)
        self.events = self.events[-5000:]
        event_epoch = self._event_epoch(event.timestamp)

        if event.event_type == "network.dns":
            self._remember_dns(event, event_epoch)
        elif event.event_type == "network.packet":
            destination = str(event.data.get("dst_ip") or event.network.get("dst_ip") or "").strip()
            context = self._dns_context.get(event.host_id, {}).get(destination)
            if context:
                domain, seen, dns_event_id = context
                age = event_epoch - seen
                if 0 <= age <= 3600:
                    event.data.setdefault("domain", domain)
                    related = list(event.data.get("related_event_ids") or [])
                    if dns_event_id not in related:
                        related.append(dns_event_id)
                    event.data["related_event_ids"] = related[-32:]
        intel = self.threat_intel.enrich_event(event)
        if intel:
            event.enrichment["threat_intel"] = intel
            event.data["indicator_score"] = max(float(event.data.get("indicator_score", 0)), min(100, intel["confidence"] * 100))
        event.data["mitre_techniques"] = techniques_for_event(event)
        finding = self.behavior.evaluate(event)
        if finding.score:
            event.data["behavior_score"] = max(float(event.data.get("behavior_score", 0)), finding.score)
            event.data["behavior_reasons"] = finding.reasons
        pending_alerts: list[SecurityAlert] = []
        fresh_alerts: list[SecurityAlert] = []
        pending_incidents: dict[str, SecurityIncident] = {}
        for alert in self.detector.evaluate(event):
            duplicate = self._deduplicate_low_alert(alert, event_epoch)
            if duplicate is not None:
                # The event is still fully retained by the event pipeline. Only
                # the alert/incident cardinality is collapsed.
                event.risk_score = max(event.risk_score, duplicate.risk_score)
                pending_alerts.append(duplicate)
                if duplicate.correlation_id:
                    incident = self._incident_index.get(duplicate.correlation_id)
                    if incident is not None:
                        incident.updated_at = event.timestamp
                        incident.risk_score = max(incident.risk_score, duplicate.risk_score)
                        incident.severity = self.risk.severity(incident.risk_score)
                        pending_incidents[incident.incident_id] = incident
                continue

            corr = self.correlation.add(alert)
            if corr.score_bonus:
                alert.risk_score = min(100, alert.risk_score + corr.score_bonus)
                alert.severity = self.risk.severity(alert.risk_score)

            self.alerts.append(alert)
            fresh_alerts.append(alert)
            pending_alerts.append(alert)

            incident_id = self._correlation_incidents.get(corr.incident_key)
            incident = self._incident_index.get(incident_id) if incident_id else None

            if incident is None:
                incident = SecurityIncident(
                    title=alert.title,
                    host_id=event.host_id,
                    severity=alert.severity,
                    risk_score=alert.risk_score,
                )
                self._attach_threat_family(incident, alert)
                self.incidents.append(incident)
                self._incident_index[incident.incident_id] = incident
                self._correlation_incidents[corr.incident_key] = incident.incident_id
                self._incident_correlation_keys[incident.incident_id].add(corr.incident_key)

            incident.alert_ids = list(dict.fromkeys(
                [*incident.alert_ids, *corr.related_alert_ids]
            ))[-100:]

            for related in self.alerts:
                if related.alert_id in incident.alert_ids:
                    related.correlation_id = incident.incident_id

            incident.risk_score = max(incident.risk_score, alert.risk_score)
            incident.mitre_techniques = sorted(set(
                incident.mitre_techniques + alert.mitre_techniques
            ))
            incident.summary = (
                f"{len(incident.alert_ids)} correlated alert(s); "
                f"risk {incident.risk_score}; MITRE "
                f"{', '.join(incident.mitre_techniques) or 'none'}."
            )
            incident.severity = self.risk.severity(incident.risk_score)
            incident.updated_at = event.timestamp
            event.risk_score = max(event.risk_score, alert.risk_score)
            pending_incidents[incident.incident_id] = incident
        self.alerts = self.alerts[-5000:]
        self.store.persist_ingest(event, pending_alerts, pending_incidents.values())
        if fresh_alerts:
            self.autonomy.on_alerts(fresh_alerts, self.events)




