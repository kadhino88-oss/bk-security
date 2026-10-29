# Phase 13 — Windows installer validation

Date: 2026-10-12 (Europe/Zurich)

## Candidate and initial machine state

Candidate: `v1.0.0-3a43e61a67fb1fc8`; installer SHA-256 `c5aae03a9696af07ab26de6cc6e018bf25096778090a977e241cf8b0826855a3`.

Before this validation attempt, `C:\Program Files\BK Security\resources\release-manifest.json` already identified the exact candidate. The existing runtime log also contained `package_integrity_verified`, `backend_spawned`, and `desktop_started` records for this build at 2026-10-12T08:32Z. These are prior machine records, not results from the current launch attempt. The registry contained two BK Security uninstall entries pointing to the same install directory.

## Attempt and result

- The installed executable displayed a Windows elevation request. After the user handled it, the app did not expose a targetable window or remain running in this validation session.
- Starting `Uninstall BK Security.exe` directly was blocked by product policy (`product policy blocks this app`). The user then completed removal through Windows Settings and reported it done. A subsequent machine check confirmed that `C:\Program Files\BK Security`, its executable, and its installed release manifest are absent. A duplicate/stale BK Security uninstall registry entry remained after this removal and was later cleaned up; see the applied-cleanup record below.
- Before uninstall, a local backup of the per-user data directory was created with access restricted to the current user and SYSTEM. It contains 122 files (73,468,520 bytes). After uninstall, all 122 files still match the backup by SHA-256; `credentials.dat`, `security.db`, and other user data were not changed.
- The user then launched the verified candidate installer and handled its Windows elevation prompt. The installed release manifest identifies build `v1.0.0-3a43e61a67fb1fc8`, matching the installer SHA-256 `c5aae03a9696af07ab26de6cc6e018bf25096778090a977e241cf8b0826855a3`. The app runtime log recorded `package_integrity_verified` at 2026-10-12T16:23:51.679Z, `backend_spawned` at 16:23:52.152Z, and `desktop_started` at 16:24:01.829Z for that build. The desktop login window was visible; no credentials were submitted.
- After reinstall, the per-user directory still contains 122 files. `credentials.dat` is byte-for-byte identical to the protected backup (SHA-256 `78f6a13db8850526c8c58298866032ac5eae735cf6e7fcfe3380fe8fe9180f06`). Both the saved and active `security.db` pass SQLite `PRAGMA quick_check`. A consistent read-only comparison found every prior event, alert, audit, and incident row still present and byte-identical; all prior row IDs are present. One existing host row has updated `last_seen` and `data`, with no host row missing. At that snapshot the active database held 40,962 events, 32 alerts, 22 audit records, 24 incidents, and 2 hosts; the backup had 40,610 events, 31 alerts, 21 audit records, 23 incidents, and 2 hosts. The active database hash differs from the backup.
- Two registry uninstall entries pointed to the same BK Security uninstall executable after reinstall. The stale entry was subsequently removed by the guarded elevated cleanup recorded below.

## Status

The interactive uninstall, user-data retention check, reinstall of the exact candidate, package-integrity startup, and desktop launch to the login screen were completed and observed. During follow-up, a local `GET /health` returned `status=ok`, build `v1.0.0-3a43e61a67fb1fc8`, and integrity score 100 from the installed backend. The build gate records the post-build smoke as passed.

The installed service also returned HTTP 200 for the dashboard root and its referenced JavaScript and CSS assets; the HTML contained the dashboard root mount element. An unauthenticated `GET /api/v1/alerts` returned HTTP 401 as required. Those earlier checks confirmed static delivery and the authentication boundary. After the user said they were already connected, a read-only inspection of the running installed desktop window showed the SOC dashboard, a `Sign out` control, and populated summary metrics. This confirms an authenticated dashboard session on 2026-10-12. No credentials were entered during this inspection, and the capture-start control was not clicked.

Read-only comparison confirmed that `d1f08d36-26f7-50ed-a276-c4fa5eff449c` is the current key generated from the configured app ID and `c5c23a17-7cae-5c52-bff6-fc3960942eef` is stale. The guarded cleanup script [cleanup_stale_bk_security_uninstall_entry.ps1](../scripts/cleanup_stale_bk_security_uninstall_entry.ps1) passed its dry-run and refused to mutate the registry from a non-elevated session. The user then ran it with `-Apply` in elevated PowerShell. Its output reported `stale duplicate removed; current entry verified` and created the recovery export `C:\Users\FEUCOM\AppData\Local\Temp\bk-security-stale-uninstall-20261012-202515-c6e9438861ef402db0ec5a0ef8856297.reg`. A follow-up machine check confirmed the current key exists, the stale key is absent, the export exists, and `/health` still reports `ok`, build `v1.0.0-3a43e61a67fb1fc8`, integrity score 100.


First-run credential creation and secure-store handling were not directly observed; the later authenticated dashboard session confirms access to the installed SOC. The bounded loopback capture was executed separately; see [the Phase 6 real-world validation report](PHASE6_REAL_WORLD_VALIDATION.md). It does not validate live capture initiated from the packaged desktop UI.

## Installed runtime dashboard recheck — 2026-10-23

- The user launched the installed application. `C:\Program Files\BK Security\BK Security.exe` exists. The local backend returned HTTP 200 from `/health` with build `v1.0.0-6b59796cf4806707`, `capture_mode=stopped`, and integrity score 100.
- The dashboard root returned HTTP 200 with its mount element; its JavaScript and CSS assets both returned HTTP 200. The served JavaScript contains the capture panel but does not contain the current source strings for the Response Desk or required Orbis attribution, confirming that those source changes are not present in this installed bundle.
- Unauthenticated `GET /api/v1/alerts` and `GET /api/v1/capture/capabilities` returned HTTP 401, preserving the authentication boundary. No token was read or submitted.
- The Windows UI inventory returned no app windows and `sky.list_apps` timed out through its prescribed recovery. No UI control was inspected or clicked. No capture-start request or Windows response action was issued.
