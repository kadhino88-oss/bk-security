# Phase 7 — Production hardening and V1 release

## Release intent

Phase 7 prepares BK Security V1 for local Windows distribution while preserving the Phase 6 impact-zero boundary. It does not enable Windows response adapters. Packaged capture starts in simulation mode, live capture requires an explicitly selected Npcap interface, the API is loopback-only, and `BK_SECURITY_WINDOWS_RESPONSE` is forced to `0`.

The Phase 6 validation report and controlled-response protocol are included with the release unchanged. The controlled-response protocol remains **NO-GO**. The 2026-10-06 build had no interactive install validation; a later install and launch were validated on 2026-10-08 as recorded below. Bounded endpoint Wi-Fi capture has since been validated on 2026-10-12; whole-network visibility and Windows response adapters remain unvalidated.

## Production changes

- Electron now validates the packaged build identity and SHA-256 inventories before startup, checks that the backend health response matches the packaged version/build, and binds the backend to loopback on a validated port.
- The desktop process starts a backend supervisor, requests authenticated graceful shutdown, waits for process closure, and has a bounded force-stop fallback. Unexpected backend exits receive at most three restart attempts in a minute.
- Packaged child processes inherit only an explicit operating-system environment allowlist and selected capture settings. Five distinct role credentials remain encrypted with Windows `safeStorage`; operational logs whitelist fields and rotate separately from the append-only SQLite security audit.
- The setup screen collects credentials for all five roles required by the backend. Production validation rejects weak or incomplete credentials, missing auth secret, wildcard CORS, non-loopback bind, invalid capture mode, live capture without a selected interface, and any response value other than `0`.
- Flow-history retention is bounded with an LRU limit; existing event, alert, database-write, and WebSocket bounds remain in place. Performance probes use temporary data and synthetic events only.
- Build scripts align the V1 version, verify locked Python dependencies and invoke the already-installed Vite/Electron Builder Node CLIs directly, create unique output directories, build the dashboard and bundled backend, and record an integrity manifest, installer SHA-256, build identity, and Authenticode status. Existing `dist` artifacts are not overwritten.

## Build and validation record

The Windows build script runs the full Python suite, Electron tests, syntax compilation, production preflight, API restart/persistence canary, synthetic bounded-ingest probe, package inventory/hash verification, known-secret pattern scan, and packaged backend API/dashboard/graceful-restart/SQLite smoke test. It creates `build-metadata.json` and `gate-state/release-gate.json` beside the installer. Those machine-specific records are authoritative for the exact test counts, installer SHA-256, build identity, signature status, and gate result.

An NSIS install is configured per-machine and requests interactive administrator approval. Automated build metadata records install/uninstall as not run when an interactive administrator session is unavailable. A separate interactive install and launch was completed on 2026-10-08; uninstall remains untested.

### Execution status on 2026-10-06

- Python regression suite: **159 passed**; Electron lifecycle/security suite: **14 passed**.
- Python source compilation: **105 files**; production runtime preflight and API restart/persistence canary: **passed**.
- Dashboard production assets built successfully into an isolated, timestamped staging directory. The PyInstaller backend completed once, but the package manifest exposed and then received a fix for generated-directory filtering.
- A clean backend rebuild stopped during PyInstaller collection with `No space left on device`. After removing only incomplete Phase 7 build folders, the C: drive had **187 MB free**, which is insufficient for Electron/NSIS packaging and packaged-runtime validation.
- Therefore no new V1 installer or SAFE gate record has been produced. The final installer hash, Authenticode status, and packaged-runtime smoke remain **not assessed**. The current-user and local-machine certificate stores contain **no currently valid Code Signing certificate with a private key**, so Authenticode signing is unavailable on this host. Existing release artifacts and Phase 6 evidence were retained; the controlled-response protocol remains **NO-GO** and `BK_SECURITY_WINDOWS_RESPONSE` remains `0`.

### Execution status on 2026-10-08

- Windows build completed with release gate **SAFE**. Version `1.0.0`, build ID `v1.0.0-999f4923ee1868cb`.
- Release build validation: critical suite **68 passed**, Python suite **161 passed**, Electron suite **14 passed**, Python syntax compilation **105 files**, production preflight, packaged-backend/API/dashboard smoke, restart/persistence canary, package inventory and secret scan all passed.
- Synthetic ingest probe: **2,000 events**, 2,403.47 events/s including database flush, p50 0.0592 ms, p95 0.1517 ms, writer healthy. This is not a live-NIC performance result.
- Installer: `dist/windows-20261008-120507-83f706/BK Security Setup 1.0.0.exe`; SHA-256 `b63a80e2dd24f25eeb2af7f7d26ba63f10184d514dfee9ac743671b7c967a2b7`; Authenticode **NotSigned**.
- Interactive per-machine installation completed on 2026-10-08. The installed app was launched, and the new dashboard pathway was visually confirmed. Installed `app.asar` and dashboard assets matched the built package. Uninstall and first-run credential setup were not tested.
- After the release build, the Windows diagnostic script was corrected to use isolated pytest temp storage and fail on test errors. The updated script passed on this host; its contract test and full suite reported **162 passed**. This validation-tool-only change does not alter the installed runtime package.
- At the time of this Windows/Npcap diagnostic, the process was not elevated, so live capture was correctly unavailable. See [Windows/Npcap validation](WINDOWS_NPCAP_VALIDATION_20261008.md). Later loopback and bounded endpoint Wi-Fi capture results are recorded in the [Phase 6 report](PHASE6_REAL_WORLD_VALIDATION.md).

### Capture-readiness follow-up build on 2026-10-08

- The dashboard displays current capture mode, Npcap/Scapy/elevation/loopback readiness and pipeline counters, with a loopback-only live-start action. API capability diagnostics report why live capture cannot start. The packaged default remains simulation, and response execution remains disabled.
- Reproducible `scripts/build_windows.ps1` completed with release gate **SAFE**. Build ID: `v1.0.0-a7d1694f5dc48d19`; installer: `dist/windows-20261008-134005-5999cb/BK Security Setup 1.0.0.exe`; SHA-256: `53925eb400db911e0e845de980b8e58663dac971f1d693de449b6d5aa428266a`; Authenticode: **NotSigned**.
- Results: **68** critical tests, **165** Python tests, **14** Electron tests, **105** Python files compiled, packaged-backend production/API/dashboard/restart/SQLite smoke passed, restart/persistence canary passed, and a 2,000-event synthetic probe measured **2,602.73 events/s**, p50 **0.0629 ms**, p95 **0.1826 ms**. These figures are synthetic and are not NIC capture performance results.
- A bounded elevated loopback validation completed with one packet, linked detection, incident/Threat Family, and valid AI evidence/provenance; policy held the proposed BLOCK as dry-run ALERT. No packet was persisted, and no adapter executed. The dashboard button click path itself remains unverified. Wi-Fi packet capture, whole-network visibility, Windows response execution, interactive uninstall, first-run credential setup, and signature remain unvalidated or unavailable as documented.
- The build uses the installed Vite and Electron Builder CLIs directly, without requiring the broken global npm shim. The NSIS step retries once in a fresh output directory after a packaging failure.
- Commercial readiness still requires a valid signing certificate and a resolved Npcap redistribution license before bundling it with BK Security. Network-wide Wi-Fi coverage also requires AP/controller/gateway telemetry or a mirrored sensor deployment; one endpoint's local adapter does not provide all-client visibility. See [capture and Wi-Fi readiness](WINDOWS_CAPTURE_AND_WIFI_READINESS.md).

### Subsequent endpoint Wi-Fi validation — 2026-10-12

The user ran the bounded Npcap validator from elevated PowerShell. It passed with 202 IPv4 packet events involving `192.168.1.121`, a five-second capture window, temporary SQLite removed, no raw packet storage, no probe traffic, and no response adapters. This confirms endpoint capture and event ingestion only; the packaged dashboard start button, detection/incident provenance for the observed Wi-Fi traffic, and whole-network visibility remain unverified. Full details are in the [Phase 6 report](PHASE6_REAL_WORLD_VALIDATION.md).

### Capture-readiness UX and Wi-Fi endpoint selector build on 2026-10-08

- The dashboard now explains missing live-capture prerequisites, restricts start/stop controls to admin/analyst roles, and allows an operator to select a discovered Npcap interface. Selecting Wi-Fi means this endpoint's adapter only; the app still defaults to simulation and starts live capture only after operator action.
- Build ID: `v1.0.0-d9a790693a24ee40`; installer: `dist/windows-20261008-142925-eca436/BK Security Setup 1.0.0.exe`; SHA-256: `5337e3f7d56fd6dee8545d52297153c1c6a8d794d432f5fa4581361941fbe7ad`; Authenticode: **NotSigned**; release gate: **SAFE**.
- Validation passed: **68** critical tests, **168** Python tests, **14** Electron tests, **106** Python files compiled, packaged backend production/API/dashboard/graceful-restart/SQLite smoke, API restart/persistence canary, and synthetic ingest probe (**2,802.14 events/s**, p50 **0.068 ms**, p95 **0.1503 ms** for 2,000 events). Performance results are synthetic, not Wi-Fi/NIC measurements.
- The per-machine installer returned exit code **0**. All **1,319** manifest-listed installed resources and `app.asar` matched the validated package; the launched backend health response reports this build ID with integrity score **100**.
- The first release-gate attempt hit a 2-second timeout on packaged login. The packaged validator was updated to allow 10 seconds and now has a regression test; a new build and full gate then passed.
- No dashboard start-button click or screenshot-based UI inspection was completed because native windows were unavailable in the UI automation inventory. No new live packet capture was run after installing this build; the prior bounded loopback result remains separately recorded. Wi-Fi packet capture, whole-network client visibility, Windows response execution, interactive uninstall, credential-first-run and code signing remain unvalidated or disabled.
- `BK_SECURITY_WINDOWS_RESPONSE=0` remained enforced throughout. The Phase 6 response protocol remains **NO-GO**.

## Signing and remaining boundaries

Authenticode signing requires a trusted code-signing certificate and private key available to the release operator. No certificate is assumed or created by these scripts. An unsigned installer is recorded as `NotSigned`; the release gate permits that state for local V1 validation but does not describe the installer as signed or publisher-verified.

Live Npcap capture remains an operator-selected runtime configuration. The release build and its smoke tests use simulation mode and synthetic traffic. Windows response adapters remain disabled, no BLOCK/ISOLATE/TERMINATE_PROCESS action is run, and the Phase 6 NO-GO protocol is unchanged.

## Operator follow-up

Before wider distribution, an administrator should validate first-run `safeStorage` credential initialization, clean close, and uninstall on a disposable Windows machine. The per-machine install and dashboard launch were validated on 2026-10-08. If the organization requires a signed installer, configure its Authenticode certificate and timestamp service in the controlled release environment, then rebuild and verify the signature. Any future real response validation requires a separately approved revision of the controlled-response protocol.
