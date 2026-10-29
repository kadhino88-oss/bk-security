# BK Security R15 Changes

## Security Brain Mode

R15 adds a live SOC visualization named **Security Brain**.

### Data path

`Network / Endpoint / LAN sensors -> SecurityEvent -> SecurityCore -> topology graph -> SOC WebSocket -> Security Brain`

The Brain Mode reuses the existing read-only topology model. It does not introduce a parallel capture pipeline.

### Dashboard

- Central BK Security Core visualization.
- Host, process, LAN device and destination nodes.
- Relationship edges from observed telemetry.
- Risk-aware host highlighting from active alerts.
- Click-to-inspect node details.
- Related incident context when available.
- 15-minute bounded window for live rendering.
- Existing topology panel retained.

### Validation

- Python tests: 93 passed, 1 skipped.
- Python compile/release gate: passed.
- Static dashboard JavaScript syntax: passed with Node `--check`.

### Build note

The environment used for this consolidation did not have the Vite dependency cache available, so the existing static dashboard was updated directly and the React source was updated in parallel. On Windows, `npm install` followed by `npm run build` can regenerate `dashboard/static` from the React source when registry access is available.
