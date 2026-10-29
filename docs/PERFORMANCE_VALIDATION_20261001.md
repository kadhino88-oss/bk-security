# BK Security performance validation — 2026-10-01

## Synthetic SQLite ingest benchmark

Command:

```powershell
.venv\Scripts\python.exe scripts\benchmark_ingest.py --events 1000
```

These runs used the local Windows/Python environment and synthetic `network.dns` events. The number includes database flush time, but does not model a real NIC, packet decode, high-cardinality detections or concurrent users.

| Measurement | Synchronous baseline | Batched writer |
| --- | ---: | ---: |
| Events/second including flush | 50.76 | 2,554.21 |
| Ingest call p50 | 18.8117 ms | 0.1165 ms |
| Ingest call p95 | 25.6522 ms | 0.3363 ms |
| SQLite writer batches | 1,000 event transactions | 8 batched transactions |

On a repeat run with the same 1,000-event command, the batched writer measured **1,858.54 events/second**, **0.1143 ms p50**, **0.2823 ms p95**, and 9 database batches. The run-to-run throughput variation is recorded instead of treating one synthetic sample as a guaranteed rate.

On this synthetic run, throughput was about **50× higher** and median ingest-call latency about **161× lower**. The bounded queue has capacity 4,096; writes apply backpressure instead of silently dropping telemetry. The writer reported healthy after all 1,000 events were flushed.

These figures are local measurements, not a production SLA. Representative live capture and sustained Windows load still need target-machine validation.

## Implementation validated by tests

- Bounded queued writes batch events, alerts and incidents atomically.
- Reads flush earlier queued writes before returning.
- Shutdown flushes and closes the background writer.
- Queue saturation blocks producers; it does not discard events.
- Incident status writes flush earlier queued snapshots before recording the transition and audit row.
