# Phase 5: Response, Policy, and Audit

## Roles

| Role | Capability |
| --- | --- |
| viewer | Read investigations, response actions, and audit |
| analyst | Investigate and prepare response plans |
| approver | Approve protected execution or rollback plans |
| responder | Execute approved plans and verified rollbacks |
| admin | Administration and plan preparation; admin is not a substitute for approver or responder |

Configure the separate account passwords with **BK_SECURITY_APPROVER_PASSWORD**
and **BK_SECURITY_RESPONDER_PASSWORD**. Production startup rejects
development-only defaults, just as it does for the existing accounts. Keep the
approver and responder credentials under separate control.

## Response flow

1. POST /api/v1/response/plan records the deterministic policy decision and a
   plan containing the action, target, reason, risk, alert/incident/evidence
   references, approval requirements, dry-run state, and safety conditions.
2. POST /api/v1/response/approve/{plan_id} accepts approval only from the
   approver role. Approval expires after five minutes and cannot be used by the
   same identity that executes the plan.
3. POST /api/v1/response/execute takes the plan_id. The responder role cannot
   alter the approved action or target. Repeating an execution returns the
   original result instead of invoking an adapter again.
4. GET /api/v1/response/actions returns persisted plan and execution states.
   GET /api/v1/response/audit returns the response lifecycle entries from the
   audit store.
5. Reversible rollback requires a separate approver decision via
   POST /api/v1/response/approve-rollback/{execution_id}. A responder then
   calls POST /api/v1/response/rollback/{execution_id}. Rollback reports
   success only after verification.

Plans default to dry-run. A dry-run never calls an adapter. A plan created as a
dry-run cannot later be converted into a live plan; create a separate plan for
live execution. BLOCK, ISOLATE, and TERMINATE_PROCESS require explicit approval
even when configured by policy. An AI recommendation remains a proposal and
cannot override the configured severity policy.

## Dashboard path

The dashboard Response desk reads the authorized response action history and
audit endpoints. Admins and analysts can prepare a policy-selected plan from an
open incident only when the incident has a recorded host target and linked
alerts. The dashboard hard-codes `dry_run: true`, links the plan to the incident
and its existing alert IDs as evidence,
and does not expose approval, execution, or rollback controls. Other signed-in
roles can review history according to the API role policy. This UI path records
a plan and audit entries; it does not block, isolate, terminate, or otherwise
change the target.

## Windows adapters

Windows firewall and process adapters belong in the privileged response
executor. The API process uses an authenticated IPC proxy when
BK_SECURITY_WINDOWS_RESPONSE=1 is set on Windows; it does not load the direct
Windows adapters. The IPC request carries the execution ID and approval
evidence. The privileged service independently verifies distinct Ed25519
signatures from an approver and responder over the same operation, action,
target, execution ID, and expiry before issuing a one-use grant. The public IPC
has no `issue_grant` operation.

The verifier and public-key trust store must be supplied by privileged-service
startup; the API's role and approval fields alone are not sufficient. Private
signing keys stay outside the API process. Production must keep responses
disabled until public-key provisioning, Windows ACL checks for state/audit/key
material, service startup and installer wiring, and Windows VM validation are
complete. Those deployment checks are not established by Linux unit tests.
Firewall changes use named BK Security rules, bounded PowerShell invocations,
and state verification. ISOLATE applies an outbound firewall rule to the local
host only. TERMINATE_PROCESS rejects reserved and protected process IDs and is
explicitly non-reversible.
