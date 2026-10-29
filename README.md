# BK Security V1 — Consolidated Source

BK Security is the security platform under BK ENTREPRISE. This bundle consolidates the development work into one codebase instead of requiring installation of intermediate v0.x packages.

## Architecture

Sensors -> SecurityEvent -> Threat Intel -> Behavior -> Detection -> MITRE -> Correlation -> Incident -> AI Security SOC -> Response Engine -> SOC API/WebSocket -> Dashboard -> Electron.

## Run the Core

```powershell
python -m pip install -e .
python -m bk_security.desktop_backend
```

Default API: `http://127.0.0.1:8000`

## Test

```powershell
pytest -q
```

## Dashboard

The API serves the dependency-free SOC dashboard at `/`; its static assets are under `dashboard/static/`. The React/Vite source remains available for development builds.

```powershell
cd dashboard
npm install
npm run build
```

## Windows installer

Run from the repository root in PowerShell on Windows 10/11 x64:

```powershell
.\scripts\build_windows.ps1
```

The build requires PowerShell 7+, Python 3.11+, Node.js 22/npm, network access on the first build to fetch the locked Electron 44.5.1 runtime, the dependencies from both npm lockfiles, and the exact Python versions in `requirements-build.lock`. It produces a timestamped backend, an NSIS installer, a resource integrity manifest and a final release-gate record without replacing earlier release outputs. The installed app's first-run screen initializes all five role passwords and saves them through Electron `safeStorage`. The per-machine installer requests Windows administrator approval; installation and uninstall are separate from package validation.

To create a checksummed consolidated **source** bundle without including local databases, logs, caches or virtual environments:

```powershell
python scripts/package_consolidated.py
```

## Capture modes

- Packaged BK Security starts in `simulation` mode. No network interface is captured automatically.
- Live Scapy/Npcap capture requires `BK_SECURITY_CAPTURE_MODE=live` and an explicitly selected `BK_SECURITY_CAPTURE_INTERFACE`.
- The loopback interface can be selected for local validation. Select a Wi-Fi interface only when that capture scope is intended.
- `BK_SECURITY_MAX_EVENTS_PER_SECOND` controls packet-event rate limiting.

## Production security

Production requires five distinct passwords (Admin, Analyst, Viewer, Approver, Responder), a 32-byte authentication secret, explicit CORS configuration, and a valid capture mode. The desktop setup screen generates the authentication secret and stores all credentials through Windows `safeStorage`; no credentials are stored in the dashboard or package. `BK_SECURITY_WINDOWS_RESPONSE` is forced to `0` by Electron for this V1 release.

## Current validation

Phase 6 validated the loopback-only Npcap path and complete SOC/policy dry-run with **145 passing Python tests** while Windows response actions remained disabled. Phase 7 build, installer, signature and install/uninstall results are recorded in [the V1 release report](docs/PHASE7_PRODUCTION_HARDENING_RELEASE_V1.md) and [the release checklist](docs/V1_RELEASE_CHECKLIST.md). A local NSIS package is unsigned unless an Authenticode certificate is provisioned.

## BK product implementation

BK Security has its own event contract, sensor modules, correlation logic, SOC API and response policy. The current source does not import or bundle PCYBOX Orbis code and does not require Orbis at runtime. It is developed as a BK product from BK's feature requirements. Third-party Python and JavaScript dependencies retain their own license terms.

See [ARCHITECTURE.md](ARCHITECTURE.md) and [docs/BK_PRODUCT_ARCHITECTURE.md](docs/BK_PRODUCT_ARCHITECTURE.md) for implementation boundaries and current capability status.

The original BK Security V1 architecture document is preserved verbatim at [docs/BK_SECURITY_V1_ARCHITECTURE_TECHNICAL_SPEC.txt](docs/BK_SECURITY_V1_ARCHITECTURE_TECHNICAL_SPEC.txt). Its Section 51 is the required quality gate: a feature is not complete until implementation, matching tests, integration into the product path, and validation are all evidenced. Work follows its Section 52 sequence; current validation and provenance limits are recorded in the docs.

## Network topology and LAN discovery

- GET /api/v1/network/topology?minutes=60 returns an authenticated host/process/destination graph with DNS aliases and ARP-discovered devices.
- The dashboard renders a live-updating graph of host, process, socket/packet destination and LAN-device relationships.
- Start the LAN sensor with POST /api/v1/sensors/lan/start.
- POST /api/v1/lan/discover requires an explicit interface and subnet; scans are limited to a private/link-local subnet with at most 254 usable hosts.
- Live ARP discovery requires Scapy, Npcap, and administrator privileges. Starting the sensor does not probe the network.


## Windows production handoff

Run `scripts/preflight_windows.ps1` from an elevated PowerShell only for the separate Npcap/environment checks. The V1 packaging gate itself runs without enabling live capture or Windows response actions.
## R16 alert-noise hardening

- First-seen destinations are retained as behavioral telemetry but do not generate alerts on their own.
- Repetitive network behavior raises a detection when the rolling beacon threshold is crossed, rather than once per packet.
- This reduces normal HTTPS/QUIC traffic alert storms while preserving deterministic suspicious-process, suspicious-port, IOC, and correlated-behavior detections.
# bk-security
