# Windows / Npcap validation — 2026-10-08

## Environment diagnostics

- Windows 11, build 22631; PowerShell 7.6.5; Python 3.14.8; Scapy 2.7.0.
- Npcap service: **Running**. Npcap detected at `C:\Program Files\Npcap`.
- Windows reports Wi-Fi up; Scapy enumerates seven interfaces, including Wi-Fi, WSL virtual Ethernet and loopback.
- The validation process was not elevated. `LivePacketCapture.available()` correctly returned **False**; no live capture was started in this run.
- An earlier elevated, loopback-only capture and event-to-incident/Threat Family validation are recorded in [Phase 6 real-world validation](PHASE6_REAL_WORLD_VALIDATION.md). At the time of this original 2026-10-08 check, live Wi-Fi capture had not yet been validated.

## Validator correction and results

The first run of `scripts/validate_windows.ps1` could not enumerate pytest's default `%TEMP%\pytest-of-FEUCOM` directory (`PermissionError: WinError 5`). Pytest reported setup errors, but the script still printed “Validation complete” and returned success.

The validator now supplies a unique `build/windows-validation-<id>/pytest` base directory and throws when pytest exits nonzero. A contract test covers both behaviors.

- Validator contract tests: **11 passed**.
- Windows validation script after correction: **165 Python tests passed**; exit code **0**. Npcap/Scapy/interface diagnostics completed. `Get-NetAdapter` is denied in this session, now reported as a warning while the `psutil` interface list remains available.
- No capture, LAN scan, Windows response action, or other network operation was started by this diagnostic.

## Capture-readiness UI follow-up

- The authenticated capture capabilities route now returns Npcap, Scapy, elevation, and Npcap-loopback readiness details and explicit reasons when live capture is unavailable.
- The dashboard shows live/simulation/stopped state, interface and packet-pipeline counters. Admin/analyst users can select a discovered Npcap interface, including a detected Wi-Fi adapter; capture begins only after the explicit start action.
- `scripts/validate_windows.ps1` ran non-elevated and correctly started no capture. A separate elevated validator then passed with a one-packet `127.0.0.1:4444` loopback probe: alert linked, incident and Threat Family created, AI evidence/provenance valid, response dry-run only, no raw packet persistence.
- Wi-Fi interface discovery and selection are covered by code and tests, but this host's active Wi-Fi interface was not captured. No all-client Wi-Fi visibility is claimed.
- Dashboard production build: **PASS** (Vite 8.3.2). The preceding loopback follow-up release passed **165 Python tests**, **14 Electron tests**, **68 critical contracts**, **105 Python files compiled**, packaged-backend smoke, API canary, and release gate **SAFE**.

## Remaining validation boundary

The 2026-10-08 real capture validation exercised the sensor pipeline directly, not a dashboard button click. The Wi-Fi interface was enumerated but no Wi-Fi traffic capture was started in that run. Whole-network Wi-Fi coverage remains a separate deployment feature; see [capture and Wi-Fi readiness](WINDOWS_CAPTURE_AND_WIFI_READINESS.md).

## Current host readiness refresh — 2026-10-12

- Read-only checks found the Npcap service **Running** and the installation at `C:\Program Files\Npcap`.
- Scapy enumerated **10** Npcap interfaces, including `\\Device\\NPF_Loopback`; Windows interface discovery reported Wi-Fi **up**.
- The diagnostic process was not elevated, so `LivePacketCapture.available()` returned **False** as expected. No capture was started. This confirms current host prerequisites and interface discovery only; it does not validate Wi-Fi traffic capture, packaged-dashboard live start, or whole-network visibility.

## Installed capture-readiness build — 2026-10-08

- The dashboard now displays a direct reason when live capture controls are unavailable (role or runtime prerequisites), lets an admin/analyst select a discovered local Npcap interface, and warns that selecting Wi-Fi covers this endpoint only. The packaged default remains simulation; the operator must explicitly start capture.
- `scripts/build_windows.ps1` completed with release gate **SAFE**. Build ID: `v1.0.0-d9a790693a24ee40`; installer: `dist/windows-20261008-142925-eca436/BK Security Setup 1.0.0.exe`; SHA-256: `5337e3f7d56fd6dee8545d52297153c1c6a8d794d432f5fa4581361941fbe7ad`; Authenticode: **NotSigned**.
- Validation: **68** critical tests, **168** Python tests, **14** Electron tests, **106** Python files compiled, packaged-backend production/API/dashboard/graceful-restart/SQLite smoke, API restart/persistence canary, and release gate all passed. The **2,000-event synthetic** ingest probe measured **2,802.14 events/s**, p50 **0.068 ms**, p95 **0.1503 ms**; these are not live-NIC performance figures.
- The installer exited **0**. All **1,319** manifest-listed installed resources and `app.asar` matched the built package. The launched app's `/health` returned build ID `v1.0.0-d9a790693a24ee40` and integrity score **100**.
- The live-start button was not clicked or visually inspected by automation. The app process/window and backend were present, but the desktop UI automation inventory exposed no native app windows. No live Wi-Fi capture or all-client visibility was tested. The earlier bounded loopback capture remains recorded above and was not rerun against this build.
- The initial run of the release gate timed out on a 2-second packaged-login probe. Reproduction with a 10-second request window passed; the validator was updated to use a 10-second HTTP timeout and a regression contract test was added. The final clean build/gate then passed.

## Later bounded Wi-Fi capture — 2026-10-12

After the read-only diagnostics above, the user executed `scripts/validate_live_wifi_capture.py` in elevated PowerShell. The supplied output reports `status=passed`, 202 IPv4 packet events on `Wi-Fi` (`192.168.1.121`) within the five-second window, temporary SQLite removed, no raw packet storage, no generated probe traffic, and response adapters disabled. This validates endpoint packet ingestion only; it does not validate the packaged dashboard start button or whole-network client visibility. See the [Phase 6 report](PHASE6_REAL_WORLD_VALIDATION.md) for the full scope and limitations.
