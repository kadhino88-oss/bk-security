# Security Reliability and Anti-Regression

## Release gate and Last Known Good

`scripts/release_gate.py` runs the critical security contracts first, then the full Python suite, an in-memory Python compile check, and the API restart/canary check. The canary includes database restart, RBAC, investigation, response dry-run, simulation capture, incident resolution/reopen, and WebSocket checks. It writes release manifests atomically. A failed candidate is recorded as `BLOCKED`; it cannot replace `dist/last-known-good.json` or the prior successful `dist/release-gate.json`. A passing candidate becomes release-eligible and advances the validated LKG; the gate itself does not install/activate it. The GitHub CI workflow runs the critical golden/security tests before the complete suite.

The service layer exposes `ReliabilityService.guard_candidate(...)` for runtime activation systems. It requires critical-test, full-test, compile, integrity, and canary success. If a candidate was already activated, rollback is performed only through an injected release-slot activation callback and is successful only after the supplied post-rollback health validator passes. This source tree has no installer/update slot switcher, so deployments must supply that narrow adapter before a running binary can be switched to an older installation. `/health` returns HTTP 503 when the runtime Integrity Score is not `SAFE`, so health monitors stop treating a broken candidate as ready.

Last Known Good records the validated version, artifact digest, a configuration fingerprint, and a sanitized configuration snapshot. Keys containing secrets, passwords, tokens, or credentials are rejected. A candidate becomes Last Known Good only after its checks, integrity report, and canary pass.

## Integrity monitor

`ReliabilityService.integrity()` reports a 0–100 Integrity Score and `SAFE`, `DEGRADED`, or `BLOCKED` state for Core, Detection, Correlation, Threat Family, AI SOC, database/schema, API/RBAC, Response, Runtime, and Configuration. Database validation runs SQLite `quick_check` and verifies required tables. API/RBAC validation inspects the investigation, repair, and response-execution route permissions. Runtime validation checks sensor-manager status and the capture pipeline contract. Diagnostics do not include authentication secret values.

Authenticated read endpoints:

- `GET /api/v1/reliability/integrity` — admin, analyst, viewer
- `GET /api/v1/reliability/diagnosis` — admin, analyst
- `GET /api/v1/reliability/audit` — admin, analyst

Investigation is read-only and allows viewers. Safe repair is admin-only. Sensitive response actions retain their existing role and explicit-approval checks.

## Safe repair and audit

Only the `RepairAction` enum is accepted: restart worker, internal reconnect, cache/index rebuild, reload validated configuration, relaunch pipeline, disable an optional component, and release rollback. A runtime must explicitly register a handler for each action it supports; arbitrary commands, detector/rule changes, RBAC changes, response-policy changes, source edits, and evidence/log deletion are not valid repairs. Correlation index reconstruction is registered by default because it rebuilds derived state from persisted alerts and active incidents.

Each repair is idempotency-keyed, rate-limited per action/target, audited before and after execution, and accepted only when its required post-check passes. Repeated failures stop at the loop guard and leave the reliability state blocked or degraded for operator review. Successful validation can clear that state.

Reliability audit entries are append-only through SQLite triggers and form a SHA-256 hash chain. The read API includes the verification result and chain hashes; routine update/delete operations are rejected and altered entries break verification. Product code never edits code or security policies during recovery.

## AI SOC and Regression Guardian

Workers return structured disposition, confidence, summary, findings, recommendations, evidence, alert/event provenance, MITRE techniques, limitations, conflicts, and validation status. The orchestrator validates confidence and schema, attaches exact alert/event references, marks results without evidence or event provenance invalid, and converts contradictory benign versus suspicious/malicious conclusions to `needs_review`.

`BKRegressionGuardian` is registered as an AI SOC worker. It diagnoses the monitor state, includes check evidence, and can recommend only allowlisted repair actions. It cannot change code or approve a security-policy change. Investigation APIs link conclusions to alert, event, and incident identifiers.
