# BK Security environment validation — 2026-10-01

## Automated validation

- Full Python suite: **78 passed** in 13.67 seconds.
- Python source, tests and scripts: `python -m compileall -q bk_security tests scripts` completed successfully.
- Restart E2E (`scripts/validate_restart_e2e.py`): passed across two real API subprocesses. It exercised login/RBAC, DNS enrichment, packet detection, MITRE, AI investigation, response approval/dry-run, persistent incident transitions and audit, restart restoration, process/socket sensors, static dashboard assets, simulation capture, terminal incident separation and SOC WebSocket.
- Seven simulation scenarios passed unit/integration coverage, including DNS anomaly, IOC enrichment and a process/DNS/connection signal set consolidated into one incident.
- Electron navigation and backend-launch contracts: `npm test` passed **6 Node tests**, including denial of external links, packaged executable selection and fail-closed production mode.
- Synthetic ingest benchmark latest rerun: **1,858.54 events/s**, p50 **0.1143 ms**, p95 **0.2823 ms**, 9 SQLite batches for 1,000 events; writer healthy after flush. An earlier run measured 2,554.21 events/s. See [performance validation](PERFORMANCE_VALIDATION_20261001.md). These are not representative live-NIC benchmarks.
- GitHub Actions workflows were added but cannot be triggered from this non-Git source bundle.

## Windows capture environment

- Npcap 1.89 service was previously confirmed running; Npcap DLL and network adapters were detected.
- This validation reconfirmed the Npcap kernel service is running, Scapy imports successfully and seven Windows interfaces are enumerated (Wi-Fi, WSL virtual Ethernet and loopback are up).
- Administrator check returned **false**, so `LivePacketCapture.available()` correctly returned false. Live capture could not be attempted without elevation.
- This process is not elevated. The capture capability reports live capture unavailable until administrator privileges are available; a live packet was not captured in this session.
- Simulation capture and the event → detection → incident → SOC path passed.
- Process and socket sensors started and returned their current views through the running API. Permission-limited process visibility remains dependent on Windows access rights.
- LAN discovery remains explicitly operator-triggered and bounded to the selected private/link-local subnet; it was not run during this validation.

## Dashboard, Electron and Windows packaging

- API-served dashboard HTML, JavaScript and CSS assets returned successfully in E2E; the live dashboard login shell was also opened in a browser, static JavaScript syntax was parsed, and the SOC action/data APIs were exercised.
- A visual browser retest of the newest dashboard controls was not performed. The React/Vite bundle was not built.
- Node.js/npm are present. Electron and Vite dependencies are absent, the npm registry was unreachable, and PyInstaller was unavailable.
- The port-8000 endpoint belonged to an already-running BK Security service and was read only. A separate backend was started on port 18741 with its SQLite database isolated under `test-data`; its login screen loaded in the browser. This avoids writing to the profile database, which the sandbox cannot access.
- The build script now creates separate timestamped backend/installer output paths and configures an onedir PyInstaller backend plus NSIS packaging, but this pipeline was not executed here.
- No `.exe` or NSIS installer was produced; no signed binary is available.

## Repository and V1 sign-off

- The supplied source bundle has no `.git` metadata; branch and commit identifiers are unavailable.
- This is not a V1 release sign-off. Real elevated Npcap capture, target-machine performance, Electron runtime, packaged-backend launch, NSIS installation/uninstall and signing remain unverified.
