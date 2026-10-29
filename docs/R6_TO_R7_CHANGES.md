# BK Security r7 — build and Windows validation corrections

## Corrections

- Vite now emits the production dashboard directly into `dashboard/static`, which is the directory served by FastAPI and embedded by Electron.
- Windows build order is now: dashboard build → static asset verification → PyInstaller backend packaging → Electron/NSIS packaging.
- The Windows build script fails immediately if the dashboard entrypoint is missing after the frontend build.
- Added `scripts/validate_windows.ps1` for repeatable Windows diagnostics covering administrator elevation, Npcap service state, network adapters, Scapy, BK Security capture capabilities, and the Python test suite.
- Added regression tests for the frontend output directory, build ordering, dashboard artifact verification, and Windows validation script.

## Validation performed in the current environment

- Python tests: 79 passed, 1 skipped.
- Python compileall: passed.
- The skipped test is the Scapy-dependent live capture test because Scapy/Npcap capture is Windows-target validation work.

## Still requires a real Windows target

- Elevated Npcap packet capture.
- Real NIC packet-to-event pipeline.
- Electron runtime.
- PyInstaller Windows executable.
- NSIS installer generation.
- Installation/uninstallation and post-reboot validation.
- Production code signing.
