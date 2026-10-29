# Phase 10 — integration validation

Date: 2026-10-12 (Europe/Zurich)

## Scope and configuration

Validation was run against the current workspace sources on Windows. The test configuration forced `BK_SECURITY_CAPTURE_MODE=simulation` and `BK_SECURITY_WINDOWS_RESPONSE=0`. Pytest data and the restart canary database were isolated under the system temporary directory.

## Results

- Python suite: **168 passed**.
- Electron lifecycle and security suite: **14 passed**.
- Dashboard unit suite: **7 passed**.
- `scripts/validate_restart_e2e.py`: **PASS** across two API subprocesses.
- Focused security follow-up on 2026-10-12: **38 passed** across Electron credential/setup contracts, production credential constraints, login rate limiting, role-guarded response and incident APIs, and authenticated SOC API contracts. Rerun with pytest's cache provider disabled; no application credentials were used.

The restart canary exercised authentication and RBAC, DNS enrichment, event-to-alert and incident correlation, AI investigation evidence and provenance, incident lifecycle persistence, response approval and dry-run, endpoint-process and socket views, simulation capture start/stop, SOC views, and WebSocket snapshot delivery.

## Validation boundary

This confirms the automated API and service integration path in simulation. The focused follow-up covers automated credential/setup and role-policy contracts; it does not validate first-run credential entry or a successful sign-in through the installed dashboard. The dashboard capture-start control was not clicked in Electron, and no Npcap capture was started in this validation. Live Wi-Fi capture, whole-network visibility, installer install/uninstall, and Windows response execution were not validated here. The separate recorded loopback capture remains evidence for its earlier build and was not rerun against this workspace.

Phase 10 automated integration checks passed. This report does not sign off the overall V1 criteria in section 53; its remaining target-environment checks must stay open until separately run and recorded.

## Workspace regression retest — 2026-10-23

- Full Python suite: **197 passed** in 129.98 seconds, with `BK_SECURITY_CAPTURE_MODE=simulation`, `BK_SECURITY_WINDOWS_RESPONSE=0`, and pytest cache disabled.
- Dashboard unit suite: **25 passed**. Electron lifecycle/security suite: **14 passed**. Focused capture, dashboard contract, and bounded Wi-Fi validator tests: **28 passed**.
- `scripts/verify_build_environment.py`: passed against the exact locked Python build dependencies.
- Read-only `GET /health` against the local installed backend returned HTTP 200, build `v1.0.0-6b59796cf4806707`, `capture_mode=stopped`, and `integrity_score=100`.
- No live capture or Windows response action ran in this retest. The user-provided bounded Wi-Fi result from 2026-10-12 remains separate evidence for the validator script; it does not validate the packaged dashboard start button or the 2026-10-23 source.
- The current UI automation inventory exposed no Windows application windows, so the installed dashboard start control was not clicked. The installed backend build remains `v1.0.0-6b59796cf4806707`; dashboard source changes after the 2026-10-18 package are not confirmed in the installed UI.
- At the resource check, available memory was **0.38 GiB** and free disk space was **38.95 GiB**. The full PyInstaller/Electron/NSIS package build was deferred; no installer or release-gate result was produced.
