# BK Security V1 release checklist

## Security and product gates

- [x] Phase 6 impact-zero validation recorded: real Npcap capture restricted to `127.0.0.1`, complete detection-to-AI-SOC pipeline, response policy `ALERT`, and dry-run only.
- [x] Phase 6 evidence and controlled-response protocol retained; the protocol remains **NO-GO**.
- [x] Electron package forces `BK_SECURITY_WINDOWS_RESPONSE=0`.
- [x] Packaged startup leaves capture stopped (no fabricated packets); the authenticated dashboard requires an explicit interface selection and operator action for live capture. Simulation remains available only when explicitly requested.
- [x] Capture readiness and selectable Npcap interfaces are integrated in the dashboard; Wi-Fi is selectable with an endpoint-only coverage warning.
- [x] Production validates five distinct role passwords, authentication secret, CORS, API bind, capture mode/interface and response flag.
- [x] `safeStorage` is retained for desktop credentials; credentials and internal shutdown token are not inherited from unrelated environment variables or logged.
- [x] SQLite persistence, append-only security audit and bounded write/event buffers are retained.
- [x] Release manifest checks package version/build ID and SHA-256 for Electron files, dashboard assets and backend resources.

## Packaging and validation results

The authoritative test counts, installer path and SHA-256, signature state, package integrity result, runtime smoke result, and outstanding install/uninstall checks are recorded in [the Phase 7 V1 release report](PHASE7_PRODUCTION_HARDENING_RELEASE_V1.md) and the generated `gate-state/release-gate.json` next to the installer. Current Windows/Npcap diagnostics are in [the 2026-10-08 validation record](WINDOWS_NPCAP_VALIDATION_20261008.md).

## Current preparation checkpoint — 2026-10-12

- [x] Phase 10 automated integration validation rerun: 168 Python tests, 14 Electron tests, 7 dashboard tests, and the two-process API restart canary passed. See [Phase 10 validation](PHASE10_INTEGRATION_VALIDATION_20261012.md).
- [x] Phase 11 synthetic Windows ingest benchmark passed: 10,000 events, 1,295.89 events/s including SQLite flush. This does not validate live-NIC or representative production performance. See [Phase 11 performance validation](PHASE11_PERFORMANCE_VALIDATION_20261012.md).
- [x] Phase 12 package candidate `v1.0.0-3a43e61a67fb1fc8` built with release gate `SAFE`; installer SHA-256: `c5aae03a9696af07ab26de6cc6e018bf25096778090a977e241cf8b0826855a3`. The generated release manifest for that candidate is no longer retained in this workspace; the recorded installer and validation evidence remain in the Phase 13 report.
- [x] Phase 13 interactive uninstall/data-retention/reinstall smoke passed after the build: all 122 user-data files matched the protected backup after removal, and the verified installer restored build `v1.0.0-3a43e61a67fb1fc8`. Runtime logs, a matching local health response, the initial login window, and a later authenticated SOC dashboard session confirm package-integrity verification and desktop operation. The guarded, backup-first cleanup removed the stale uninstall registry key; follow-up checks confirmed the current key and recovery export remain and the installed service is healthy. See [Phase 13 installer validation](PHASE13_INSTALLER_VALIDATION_20261012.md).
- [x] Bounded Npcap loopback validation executed on 2026-10-12 through `scripts/validate_live_loopback_soc.py`: one localhost UDP event was captured and linked to detection, incident/Threat Family, AI evidence/provenance, and a dry-run response plan. The user-provided output reports `passed`; no adapter ran. This validates the workspace pipeline script, not live capture initiated by the packaged desktop UI. The separate endpoint Wi-Fi capture result is recorded below. See [Phase 6 real-world validation](PHASE6_REAL_WORLD_VALIDATION.md).

- [x] The release candidate's Python gate passed (168 tests); the current workspace suite was rerun on 2026-10-12 and passed 179 tests, including the bounded Wi-Fi validator tests.
- [x] Electron lifecycle, integrity and runtime-log tests passed (14 tests).
- [x] Python syntax compilation (106 files) and production configuration preflight passed.
- [x] API restart/persistence canary passed.
- [x] Dashboard assets built and packaged.
- [x] Backend packaged and passed production-mode API/dashboard/graceful-shutdown/restart/SQLite smoke.
- [x] NSIS installer built with a unique output directory and matching version/build identity.
- [x] Reproducible build script uses local Node CLIs and retries NSIS once in a fresh output folder after a packaging failure.
- [x] Secret and package-inventory scan passed.
- [x] Authenticode status recorded accurately as `NotSigned`; unsigned is acceptable for local V1 validation.
- [x] Per-machine installation and dashboard launch validated on 2026-10-08; installed resources match build `v1.0.0-d9a790693a24ee40` and the running health endpoint reports the same build ID.
- [x] Interactive Windows uninstall, data retention, reinstallation of candidate `v1.0.0-3a43e61a67fb1fc8`, authenticated dashboard session, and guarded elevated stale-key cleanup validated. First-run credential creation and secure-store handling were not directly observed. The current uninstall key and `.reg` recovery export were verified after cleanup in [the Phase 13 report](PHASE13_INSTALLER_VALIDATION_20261012.md).
- [ ] Dashboard live-start click remains unverified; the authenticated installed dashboard was re-observed on 2026-10-12, but the capture panel was unreachable to the available UI controls and no start click occurred. The successful Wi-Fi capture below was run directly through the bounded validation script, not through this desktop button.
- [x] Bounded live Wi-Fi endpoint capture passed on 2026-10-12: the user ran `scripts/validate_live_wifi_capture.py` in elevated PowerShell, and its output reported 202 normalized `network.packet` events, a removed temporary SQLite database, no raw packet storage, no generated probe traffic and no response adapters. The 11 validator tests and full 179-test Python suite passed. See [the Phase 6 real-world validation report](PHASE6_REAL_WORLD_VALIDATION.md).
- [ ] Whole-network multi-client visibility remains unvalidated. The bounded script validates only traffic involving this endpoint’s Wi-Fi IPv4 address. See [the Phase 6 real-world validation report](PHASE6_REAL_WORLD_VALIDATION.md).

## Capture control hardening follow-up — 2026-10-20

- The dashboard now fails closed when a selected non-loopback interface has a missing or unknown link state; it must report `up` before the live-start control is enabled. Loopback retains its explicit exception.
- Live start/stop API requests are routed through tested dashboard helpers. Coverage verifies bearer authorization, the selected interface payload, stopping an existing capture before replacement, and surfacing stop/start API errors.
- Validation passed: **19 dashboard tests**, **15 Python capture/API contract tests**, and a Vite production build to `work/dashboard-build-validation-20261020-capture-api`.
- In the earlier validation pass, the native-app inventory exposed no BK Security window, so no installed-dashboard click, live capture, or Windows response was performed in that pass. The checklist item for validating live-start through the installed dashboard remains open. The initial `npm test` launcher failed because its configured global `npm-cli.js` path is missing; the same dashboard test files passed using `node --test` directly.

## Installed dashboard visual recheck — 2026-10-20

- A later Computer Use session found the running `C:\Program Files\BK Security\BK Security.exe` window. The dashboard displayed `SIGNED IN · ADMIN`, `LIVE · RUNNING`, Npcap/Scapy readiness, the Wi-Fi interface selected, and an active capture with 164 events accepted and zero rejected/dropped at the time of the first capture-panel observation.
- Across successive screenshots, the Security Brain's displayed signal total rose from 463 to over 1,100; the binary sphere changed orientation, and its flow paths and activity counters changed. The same view showed 50 alerts, 44 linked incidents, and 24 Threat Families. An open critical incident was visible with risk max 98. A grouped incident `VIEW` control expanded the grouped occurrence list.
- This validates the displayed running dashboard and its animation only. The capture was already running, so the dashboard live-start click remains unverified; no stop, alarm playback, Windows response, packet-level provenance check, or complete-network coverage test was performed. The selected Wi-Fi endpoint remains limited to traffic delivered to this computer; whole-network coverage still requires an authorized mirrored feed or distributed sensors and separate validation.
- The Brain header indicated a critical signal while its critical-flow tile showed zero; the incidents list simultaneously contained a critical incident. These are different underlying counts (alerts/incidents versus flows), but the distinction should stay clear in future UI review.

## Installed backend health recheck — 2026-10-20

- The running `bk-security-backend.exe` process was observed listening on `127.0.0.1:8000`; its read-only `/health` response returned `status=ok`, product `BK Security`, version `1.0.0`, build ID `v1.0.0-6b59796cf4806707`.
- This confirms the installed backend is responding. It does not prove the new Response Desk evidence-link correction is installed; that source change was made after this build. The native-window screenshot tool previously timed out, so the updated panel's installed rendering remains unverified.

## Windows packaging preflight — 2026-10-20

- The exact locked Python build dependencies pass `scripts/verify_build_environment.py`; the local Vite CLI, Electron Builder CLI, and locked Electron executable are present.
- `scripts/build_windows.ps1` now executes the dashboard `package.json` test file list with direct `node --test` after Vite builds, avoiding the broken npm shim. It parses and stores the TAP pass count in `build-metadata.json`; the release gate requires at least **25** dashboard tests and copies the count into `release-gate.json`. The exact build command reported **25 dashboard tests passed**; PowerShell parser validation passed; release-build and gate contract tests passed (**20 passed**).
- No updated Windows package was produced in this pass. Free memory varied from **749,536 KB** (~0.71 GiB) to **1,282,196 KB** (~1.22 GiB); the latest observation was 1,282,196 KB while BK Security remained responsive. I deferred the full Python/PyInstaller/NSIS build rather than risk degrading the active desktop session. The last recorded Windows package remains build `v1.0.0-6b59796cf4806707`; it does not include the 2026-10-20 dashboard correction.

## Response desk dry-run integration — 2026-10-20

- Added a dashboard Response desk that reads `/api/v1/response/actions` and `/api/v1/response/audit`. Admins and analysts can prepare a policy-selected plan from a known open incident with a recorded host; the request is fixed to `dry_run: true` and carries the incident ID as both incident and evidence context. The desk exposes no approval, execution, or rollback action.
- Outcome labels distinguish dry-run, verified execution, unverified execution, degraded state, and verified rollback. The interface does not label an outcome verified unless the backend reports verification.
- Validation passed: **24 dashboard unit tests**, **26 Python dashboard/response API/engine tests**, and Vite production build to `work/dashboard-build-validation-20261020-response-desk-attribution`.
- The installed desktop build has not been repackaged or reinstalled with this panel, so its rendering in the installed window remains unverified. No persistent plan was created in the running user database and no Windows adapter was invoked. Phase 6 remains **NO-GO** for real Windows responses until the isolated restore-ready VM and adapter protocol checks pass.
- A 2026-10-20 read-only VM readiness check found no usable Hyper-V management service/cmdlet in the current session, false CPU virtualization capability properties, and only about 1.18 GiB free RAM at the time. Feature-state inspection required elevation and was not performed. See the [Phase 6 real-world validation record](PHASE6_REAL_WORLD_VALIDATION.md).

## Response evidence-link correction — 2026-10-20

- Review found that the first Response desk draft recorded an incident ID again as an `evidence_id`. The desk now uses only the incident's existing linked alert IDs and refuses to create a plan when those alert references are absent. Dry-run remains forced; no backend policy or Windows adapter was changed.
- The API integration case constructs an event → alert → incident chain, then verifies that the dry-run plan and response audit preserve the actual linked alert ID. Dashboard unit coverage verifies deduplication and refusal of missing evidence; the Python contract test guards the UI integration.
- Validation passed: **25 dashboard tests**, **26 targeted Python dashboard/response API/engine tests**, and Vite production build to `work/dashboard-build-validation-20261020-response-evidence-1792496722129`.
- This candidate has not been packaged or installed, and the fresh native-window screenshot attempt timed out twice. The running installed app therefore does not yet prove this correction is visible. Phase 6 remains **NO-GO** for real Windows responses.

## Source attribution and commercial-license gate — 2026-10-20

- Section 54 and the preserved Orbis terms require an exact attribution in the UI. The dashboard source did not contain it; the required wording and upstream URL are now visible in the dashboard footer, with a Python contract test guarding the source.
- Validation passed after the footer change: **24 dashboard tests**, **26 Python contract/API tests**, and Vite production build to `work/dashboard-build-validation-20261020-response-desk-attribution`. The installed app was not repackaged, so this does not prove the attribution is present in the installed package.
- Source origin/license notices match the copies in the 2026-10-18 unpacked package by SHA-256. This proves notice-file preservation for that candidate only; it does not prove a commercial grant or line-by-line provenance. The separate commercial license required by the preserved terms was not found in the reviewed files, so commercial distribution remains uncleared.

## End-user release information

See [Windows production setup](WINDOWS_PRODUCTION_SETUP.md) for Windows/Npcap prerequisites, first-run credentials, capture scope, backup/recovery, logs and response limitations, and [capture/Wi-Fi readiness](WINDOWS_CAPTURE_AND_WIFI_READINESS.md) for the limits of endpoint versus whole-network coverage and commercial redistribution prerequisites. Do not claim live Wi-Fi capture, installer uninstall or Authenticode signing unless the report records the actual check.

## Workspace regression retest — 2026-10-23

- Current workspace validation: **197 Python tests**, **25 dashboard tests**, and **14 Electron tests** passed. The focused capture/dashboard/Wi-Fi set passed **28 tests**; exact locked Python build dependencies passed the preflight.
- Read-only local backend health returned HTTP 200 for build `v1.0.0-6b59796cf4806707`; capture was stopped and integrity score was 100.
- The bounded Wi-Fi live-capture result remains the user-run 2026-10-12 result. No live capture or response adapter ran during this retest, and the packaged dashboard start click remains unverified.
- Full Windows packaging was not run with only **0.38 GiB** available memory at the resource check. The 2026-10-18 candidate does not include the later dashboard source changes; installer packaging and installed rendering remain open.

## Installed runtime dashboard recheck — 2026-10-23

- The user launched the installed application. `C:\Program Files\BK Security\BK Security.exe` exists. The local backend returned HTTP 200 from `/health` with build `v1.0.0-6b59796cf4806707`, `capture_mode=stopped`, and integrity score 100.
- The dashboard root returned HTTP 200 with its mount element; its JavaScript and CSS assets both returned HTTP 200. The served JavaScript contains the capture panel but does not contain the current source strings for the Response Desk or required Orbis attribution, confirming that those source changes are not present in this installed bundle.
- Unauthenticated `GET /api/v1/alerts` and `GET /api/v1/capture/capabilities` returned HTTP 401, preserving the authentication boundary. No token was read or submitted.
- The Windows UI inventory returned no app windows and `sky.list_apps` timed out through its prescribed recovery. No UI control was inspected or clicked. No capture-start request or Windows response action was issued.

## Enterprise roadmap workspace follow-up — 2026-10-23

- The evidence-backed local monthly activity report is integrated at `GET /api/v1/audit/monthly?month=YYYY-MM` and in the workspace dashboard. Final validation after the latest change passed **204 Python tests** and **29 dashboard tests**. The Vite production build generated the matching static dashboard bundle.
- The report distinguishes retained events, alerts, incidents, dry-runs and verified response records; it reports bounded-retention/coverage limits and explicitly leaves attacks avoided and verified threat remediation unmeasured. It is not a compliance audit or a complete multi-source customer report.
- Phase 14 has a workspace threat model and candidate profile: 1 billion events/day, 3× 15-minute burst, 30-day searchable retention, candidate 99.9% ingestion availability, RPO ≤5 minutes and RTO ≤60 minutes. These are design assumptions awaiting product/operations/pilot approval, not achieved capacity or contractual SLAs. See [Phase 14 enterprise requirements](PHASE14_ENTERPRISE_REQUIREMENTS.md).
- Synthetic local ingest benchmark was rerun on this workspace: 10,000 events at 1,218.12 events/s including SQLite flush; it does not validate the Phase 14 profile. The user-provided loopback and Wi-Fi capture outputs in this conversation remain the evidence for those live captures; neither capture nor any response adapter was rerun for this workspace change.
- The installed app has not been rebuilt or updated with the monthly report. The previously observed installed build `v1.0.0-6b59796cf4806707` therefore does not establish dashboard visibility of this change. Packaging, installed UI verification, distributed ingestion, tenant isolation, HA, recovery objectives, enterprise-scale performance and pilot acceptance remain open.
- A read-only resource check after these validations found **1.30 GiB free of 7.89 GiB** while five BK Security processes, including the backend, reported responsive. The full PyInstaller/Electron/NSIS release build was deferred; no packaging attempt was made in this pass.

## Dedicated customer data-plane binding — 2026-10-23

- Added an opt-in `dedicated_customer` deployment descriptor. A fresh SQLite file is atomically bound to an opaque customer reference, stable deployment UUID and declared region. Startup refuses a different binding or populated legacy database, so old local customer data cannot silently be relabeled.
- The monthly audit API/dashboard now states the configured scope and says region attestation is unverified and enforcement is only a database startup binding. The current installed desktop remains `local_v1` until a new package configures this profile.
- Follow-up hardening makes any `SecurityStore` inherit the configured dedicated deployment identity when callers do not inject a context, and rejects an explicit context that conflicts with the process identity. Dedicated API and WebSocket tokens carry that customer and deployment scope and are rejected by another deployment. Every SQLite connection rechecks the binding, including after a database path change; the dedicated profile rejects ephemeral `:memory:` databases. Local two-database tests confirm that events, alerts, incidents, response records and audit rows remain in their own repository, and that the authenticated monthly API reports the selected database scope. Full Python regression passed **218 tests**, dashboard unit validation passed **30 tests**, and Vite 8.3.3 production build succeeded (`index-UChp7G05.js`, 280,267 bytes; `index-B-KmCCRs.css`, 43,511 bytes). These validate the workspace code and static bundle only; the installed application remains on its prior build, and no package, server isolation, or live capture was validated in this pass.
- This does **not** complete Phase 15: no separate process or host/network/cloud isolation, service/agent identities, mTLS, regional attestation, KMS data encryption, retention policy engine, deletion, backup erasure, administrator-driven account disablement, or production two-customer exercise has been validated.

## Dedicated operator session revocation — 2026-10-24

- API-issued bearer tokens now include a random session ID. Login persists that ID and its expiry in the active SQLite data plane; `POST /api/v1/auth/logout` revokes the current session, subsequent HTTP requests reject it, and the SOC WebSocket checks revocation once per second. The dashboard's Sign out control calls the endpoint, clears the local token, and warns if server revocation was not confirmed.
- Focused validation passed: **37 Python tests** across auth, deployment binding, production configuration and monthly audit; **32 dashboard unit tests**. The full Python suite then passed **219 tests**. Vite 8.3.3 production build passed to an isolated output directory; the verified JavaScript bundle was copied into `dashboard/static` after a recoverable snapshot. This does not mean a Windows package was rebuilt or installed.
- At this checkpoint, revocation was confined to one SQLite instance and an administrator could not yet revoke every session for another operator. The later admin control below adds that capability within one instance. Account disablement, IdP/MFA, and revocation propagation across replicas remain open; Phase 15 remains open.

## Provider-neutral deployment target — 2026-10-24

- The hosting direction is provider-neutral: OCI image and Kubernetes API are candidate contracts for on-premises or compatible environments; no cloud provider was selected. See [the Phase 15 portable deployment contract](PHASE15_PORTABLE_DEPLOYMENT_CONTRACT.md).
- Validation for the documentation and deployment-scope update passed: **36 targeted Python tests** across production configuration, deployment binding, token scope and monthly audit; local document/module references resolved. The focused suite was rerun with `-p no:cacheprovider` and a fresh temporary directory: **36 passed in 9.42s**.
- No image, manifest, cluster, or server network exposure was built or exercised. The existing API remains loopback-only in production. Phase 15 is still open, and Phase 16 has not started.

## Administrator session revocation — 2026-10-24

- Added an admin-only API to list active session summaries and revoke every active session for a selected account in the current SQLite instance. Summaries expose usernames, counts and latest expiry, never token IDs. Revocation is audited, takes effect on subsequent HTTP requests, and WebSockets close when their next one-second session check sees the revocation. The dashboard lists sessions for admins and confirms before revocation; this ends sessions but does not disable the account.
- Validation passed: **12 focused Python auth/hardening tests**, including a live test-client WebSocket that closes with code 1008 after admin revocation; **35 dashboard tests**; **220 Python tests** across the full workspace; and the Vite 8.3.3 production build. The generated static bundle was integrated into `dashboard/static` after a recoverable snapshot; its files matched the validated output by SHA-256.
- No Windows package was rebuilt or installed. Revocation state is local to one SQLite instance; account disablement, IdP/MFA, multi-replica propagation, tenant/region isolation, and server deployment remain unvalidated. Phase 15 remains open.

## Sensitive-field filtering at ingestion — 2026-10-24

- The shared event pipeline now redacts common credential-shaped fields, Bearer values, sensitive URL parameters, private-key blocks, and sensitive command-line arguments before detection, investigation, API response, or SQLite persistence. Values needed for detections, such as destination ports and process names, remain available. The benchmark script now pins imports to this checkout and prints `source_root`, avoiding stale copies selected by machine-level `PYTHONPATH`.
- Validation passed: **25 targeted Python tests**, **223 full Python tests**, **35 dashboard tests**, and the Vite 8.3.3 build/static bundle check from the admin-session UI change. The final default 10,000-event synthetic benchmark completed at **802.95 events/s** with a healthy SQLite writer, p50 **0.2205 ms**, p95 **0.6117 ms**. This is about **14.4× below** the 11,574 events/s average implied by the unapproved one-billion-events/day candidate profile; it is not a production capacity result. See [the Phase 11 performance record](PHASE11_PERFORMANCE_VALIDATION_20261012.md).
- The filter does not find secrets hidden in arbitrary text or encoded values and is not PII anonymization or encryption at rest. No Windows package was rebuilt or installed. Phase 15 remains open.

## Phase 16 ingestion contract, local semantics — 2026-10-26

- Added `bk_security/ingestion/`: a versioned (v1) event envelope validated against the deployment's `DeploymentContext` (tenant mismatch, unknown fields, bad identifiers, oversize and malformed input are quarantined with stable reason codes), and a file-backed SQLite `IngestionQueue` that acknowledges only after commit, deduplicates by envelope ID, applies per-agent token-bucket quotas, signals backpressure at a depth limit, replays unacknowledged leases after restart, and quarantines poison events after bounded retries.
- Validation: `tests/test_ingestion_gateway.py` passed **18 tests**; full Python suite passed **241 tests** (223 before this change).
- **Not integrated:** no API route, agent authentication, mTLS or remote listener uses this module yet (the remote-exposure barrier in the Phase 15 contract still applies). It is single-process SQLite, not a distributed queue; no throughput, loss-free, HA or capacity claim is made. Phase 16 remains open.

## Ingestion hardening and multi-OS platform layer — 2026-10-27

- A three-lens adversarial review (security, durability, integration) of the Phase 16 ingestion code confirmed defects, all since fixed with regression tests: sender-controlled event identity/enrichment/risk (now server-owned, agent types only, strict pydantic validation); no tenant binding on the queue file (now bound like the customer database); dedupe by envelope ID alone (now per agent, with conflict quarantine); acknowledgement before the customer store flushed (now flush-then-complete); monotonic-clock leases (now wall clock, owner-fenced); unbounded done/quarantine rows and raw payload retention (now pruned, sanitized payload, keyed hash only); hostile input raising 500s; blocking work on the event loop (now sync routes in the thread pool); invalid `BK_SECURITY_INGEST_*` settings (now 503 and a production configuration error).
- Added `bk_security/platforms/` (Windows, Linux nftables, macOS pf, shared psutil process adapter) behind `PlatformProvider`; response adapters stay off unless `BK_SECURITY_OS_RESPONSE=1`, which production refuses.
- Validation: full Python suite passed **322 tests** (280 before the ingestion fixes). New modules are imported statically by `bk_security.api.app`, so PyInstaller analysis should include them; no package was built.
- **Not validated:** the Linux and macOS adapters ran only against simulators of `nft` and `pfctl`; no real command, no capture outside Windows, no multi-process queue test. The re-verification workflow after the fixes failed to start (usage limit), so the fixes are checked by their tests only, not by a second independent review. Phase 16 stays open (single-host SQLite, no agent credentials, no remote listener).

## Autonomy levels — 2026-10-27

- Added per-customer autonomy levels (`bk_security/policy/autonomy.py`, `bk_security/autonomy.py`, `bk_security/api/autonomy_routes.py`): 1 observe (default), 2 recommend (dry-run plans only), 3 contain automatically (BLOCK only), 4 extended (ISOLATE/TERMINATE_PROCESS only when the operator lists them). Levels 3-4 require a recorded, time-bounded customer consent; they also require risk ≥ the configured minimum (≥50, default 80), at least one evidence event, a public non-protected target IP (private ranges protected by default), and an hourly cap. An emergency stop (admin, approver or responder) forces observe and is persisted; only admin resumes. An unreadable stored policy fails closed to stopped.
- Automatic execution goes through the existing plan → approve → execute path with two distinct system identities, so verification, rollback and audit are unchanged; every decision is audited with policy version and consent reference. Policy changes are audited with before/after.
- Validation: `tests/test_autonomy.py` passed **21 tests**; full Python suite passed **343 tests**.
- **Not validated / limits:** only the BLOCK candidate is derived from alerts (from the implicated remote public IP); ISOLATE/TERMINATE_PROCESS have no automatic trigger yet. The hourly cap and one-response-per-target memory are process-local and reset on restart. No real firewall adapter ran: tests use a fake adapter, and real OS adapters stay off (`BK_SECURITY_OS_RESPONSE`/`BK_SECURITY_WINDOWS_RESPONSE`, refused in production), so no real blocking has been validated. False-positive impact of automatic blocking on real traffic is unmeasured. There is no dashboard control yet; the operator uses the API.
