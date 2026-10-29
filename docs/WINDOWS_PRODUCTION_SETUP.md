# BK Security V1 — Windows production setup

## Prerequisites

- Windows 10 or 11, x64.
- The per-machine NSIS installer requests administrator approval during installation. The installed desktop application and first-run credential setup run under the signed-in user.
- Npcap is required only for an operator-selected live packet capture. The application starts with capture stopped and no synthetic network traffic; simulation scenarios remain available for explicit testing.
- The installed backend and dashboard are bundled. End users do not need Python, Node.js or npm.

## First launch and credentials

On first launch, create five different passwords for Admin, Analyst, Viewer, Approver and Responder. Each must contain at least 12 characters. Electron generates the authentication secret and stores the credentials with Windows `safeStorage`; the desktop UI does not require secrets to be entered into source files, the dashboard or logs.

The backend rejects missing/weak production settings, reused role passwords, wildcard CORS, a non-loopback API bind, live capture without an explicit interface, and any response setting other than `BK_SECURITY_WINDOWS_RESPONSE=0`.

The legacy `scripts/configure_windows_production.ps1` is only for operators who deliberately run/configure the backend outside Electron. It stores values as current-user environment variables; prefer the desktop setup screen for normal installation so the credentials use `safeStorage`.

## Capture and Npcap

Packaged startup defaults to `BK_SECURITY_CAPTURE_MODE=stopped`; it does not select or capture a network interface. In the authenticated dashboard, an Admin or Analyst can select a discovered interface and explicitly start live capture. For unattended startup only, configure both:

- `BK_SECURITY_CAPTURE_MODE=live`
- `BK_SECURITY_CAPTURE_INTERFACE` with the exact Npcap interface name

The app binds its API to `127.0.0.1`. Npcap and Scapy availability/interface diagnostics remain available. Select Wi-Fi only when that broader capture scope is intended. LAN discovery remains an explicit operator action and bounded to its selected private/link-local subnet.

## Data, logs and recovery

Electron keeps the encrypted credential store, SQLite database and bounded operational log in its per-user application-data directory. SQLite uses WAL and performs integrity checks. Security audit records remain in the append-only database audit table; operational log rotation does not rotate or delete audit records.

For a backup, close BK Security and copy the database plus any `-wal`/`-shm` files that remain. Do not copy a live database. To recover, stop the application cleanly, restore the last known-good database set, then restart and check the Reliability/Integrity status. Keep a separate copy of the encrypted credential file if credential recovery is required; it is tied to the Windows user profile that encrypted it.

Operational logs omit passwords, tokens, event payloads and request bodies. They roll over at 1 MiB with three retained files. The API audit log is persisted separately and remains append-only.

## Windows response policy

Windows BLOCK, ISOLATE and TERMINATE_PROCESS actions remain disabled. Electron always sets `BK_SECURITY_WINDOWS_RESPONSE=0`; policy planning remains dry-run. The controlled-response activation protocol in [Phase 6](PHASE6_CONTROLLED_RESPONSE_ACTIVATION_PROTOCOL.md) remains **NO-GO** and is not changed by this release.

## Updates, uninstall and signatures

Each build records its version, source-derived build ID, SHA-256 hashes, capture default, response flag and Authenticode status. The installer does not remove per-user application data during uninstall. This environment has no signing certificate unless the V1 release report records one as available; unsigned Windows packages will show the normal SmartScreen/unknown-publisher notice. Do not describe a `NotSigned` build as signed.
