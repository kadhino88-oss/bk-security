# BK Security product capabilities

BK Security is designed as a detection, investigation and response platform. It owns its sensor contracts and its SOC data model.

| Product area | BK Security V1 implementation | Current constraint |
| --- | --- | --- |
| Persistence | SQLite/WAL repository for events, alerts, incidents, audit, hosts and response actions; bounded event/alert history, atomic queued batches and restart hydration | Synthetic local benchmark only; representative NIC workload is not validated |
| Network capture | Scapy/Npcap live capture and deterministic simulation | Live capture requires Npcap and administrator privileges |
| Process and socket context | Periodic process and socket snapshots, PID-to-process attribution, bounded current views, deduplication and command-line secret redaction | Process visibility depends on Windows permissions; individual sensors must be started by an operator |
| DNS | Passive DNS from captured packets and explicit DNS observations | Encrypted DNS content is not visible to passive packet inspection |
| Host identity | Stable host identity and host event context | Machine identity is distinct from a boot session |
| Detection and behavior | Deterministic detection, risk scoring and rolling behavior signals with bounded host, flow, destination and observation memory | Baseline quality improves with longer lived data |
| Correlation | Host, process, destination and bounded time-window grouping | Unattributed or incomplete telemetry may not join |
| Incidents and SOC | Persistent lifecycle transitions with atomic audit records, consolidated multi-signal cases, AI analysis, MITRE context, API and authenticated WebSocket | AI output is advisory; policy controls response |
| Network topology | Authenticated API and live-updating static SOC graph aggregate packet and socket flows, DNS aliases and LAN devices | React/Vite build still needs npm dependencies; static SOC is served directly by the API |
| LAN discovery | Explicitly requested private-subnet ARP discovery | Requires Npcap, privileges and an up selected interface |
| Desktop | Electron navigation/webview policy, packaged-backend command resolution and versioned Windows build configuration | Electron runtime and NSIS build have not run in this environment |

Simulation supports normal traffic, port scan, suspicious process, beaconing, DNS anomaly, local IOC match and multi-signal attack scenarios. These generators exercise the same event/core path as the sensors and are unit-tested.

The repository contract is expressed as a Python `Protocol`; SQLite is the current implementation. Event and alert history is bounded, restored at startup, and replayed into DNS/correlation context so a process restart does not silently split an active incident. Response executions and rollback results are persisted by the response workflow, listed through the authenticated response API, and restored at startup. A real rollback still requires its explicit OS adapter to be configured; none is enabled by default.

## Integration contract

Sensors publish normalized `SecurityEvent` data. Detection and correlation consume the same event contract regardless of the sensor implementation. Collection and response remain separate; LAN probing and containment actions require explicit policy and operator intent.

## R15 — Security Brain Mode

BK Security V1 now includes a live Security Brain visualization in the SOC dashboard. The view is driven by the existing telemetry graph and SOC WebSocket snapshot rather than synthetic decorative data.

- Central node: BK Security Core.
- Dynamic nodes: hosts, processes, LAN devices and destinations.
- Relationships: observed telemetry edges from the network topology engine.
- Risk highlighting: host risk derived from active alerts.
- Inspector: click a node to inspect type, host/IP/PID/risk and related incident context.
- Window: bounded 15-minute live graph for the Brain Mode to keep rendering predictable.
- Existing Network Topology remains available below the Brain Mode for a more compact technical view.

## Enterprise target — not yet delivered

The current V1 remains a local Windows/SOC application with an in-process event bus and SQLite persistence. Its recorded synthetic benchmark does not establish distributed or billion-event capacity. The enterprise target adds isolated customer data planes, durable distributed ingestion, explicit sensor/service identities, supervised least-privilege agents, policy-controlled remediation and recovery, evidence-backed monthly reporting, and measured high-availability and recovery objectives. See [Enterprise Scale Target Architecture](ENTERPRISE_SCALE_TARGET_ARCHITECTURE.md) and section 56 of the canonical technical specification. These are roadmap requirements, not current product claims.

The Phase 14 threat model and proposed measurable load/availability/recovery profile are recorded in [Phase 14 enterprise requirements](PHASE14_ENTERPRISE_REQUIREMENTS.md). They are design assumptions awaiting product, operations and pilot-customer acceptance; they do not change the V1 capability boundary.

The workspace now also has a `dedicated_customer` deployment identity that binds a fresh, persistent SQLite database to an opaque customer reference, deployment UUID and declared region. Repository connections inherit and recheck that binding, preventing accidental reuse of a populated/unbound database or opening a bound database under another deployment identity. Dedicated HTTP/WebSocket auth tokens carry and verify the same customer/deployment scope. This does not implement server/network isolation, region attestation, mTLS, IdP/MFA, encryption at rest or remote agent ingestion; see [Phase 15 customer data plane](PHASE15_CUSTOMER_DATA_PLANE.md).
