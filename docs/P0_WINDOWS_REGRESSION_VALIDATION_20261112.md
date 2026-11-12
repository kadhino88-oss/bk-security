# P0 Windows regression validation — 2026-11-12

## Environment

- Source: `codex/p0-dual-approval` at `bd2df49`
- OS: Windows 11 (`10.0.22631.0`)
- PowerShell: 7.7.0
- Python: 3.14.8, exact versions from `requirements-build.lock`
- Node.js: 22.23.1
- Validation command: `scripts/validate_p0_windows.ps1`

## Results

| Suite | Result |
| --- | ---: |
| Python | 399 passed |
| Electron | 14 passed |
| Dashboard | 35 passed |

The script ended with `P0 WINDOWS-HOSTED REGRESSION SUITES: PASS`.

## Scope limit

This run verifies the regression suites on Windows. It does not install or
start the privileged response service, validate production ACLs or service
account isolation, execute a firewall/process action, or test rollback against
a real Windows adapter. The service installation and response-activation gates
remain closed; production response flags must stay at `0`.
