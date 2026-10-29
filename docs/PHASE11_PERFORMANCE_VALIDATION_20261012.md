# Phase 11 — performance validation

Date: 2026-10-12 (Europe/Zurich)

## Synthetic Windows ingest run

Command: `python scripts/benchmark_ingest.py --events 10000`

The benchmark ran on this Windows host against a temporary SQLite database. It ingested synthetic DNS events through `SecurityCore`; capture mode was set to simulation and Windows response actions remained disabled.

| Measurement | Result |
| --- | ---: |
| Events, including final database flush | 10,000 |
| Throughput | 1,295.89 events/s |
| Ingest latency p50 | 0.0745 ms |
| Ingest latency p95 | 0.2373 ms |
| SQLite batches | 79 |
| Writer health after flush | healthy |
| Process RSS growth | 11,812,864 bytes |
| Process CPU time | 3.2812 s |

## Validation boundary

This is a single synthetic local ingest measurement, not a production SLA. It does not exercise Npcap, real packet decoding, a physical network adapter, sustained representative Windows traffic, or concurrent operators. Section 53's real-target performance criterion remains open until those conditions are measured on a designated validation machine.

## Workspace re-run — 2026-10-23

Command: `python scripts/benchmark_ingest.py --events 10000`

The current workspace processed 10,000 synthetic DNS events through `SecurityCore` and flushed them to a temporary SQLite database. Capture and Windows response actions were disabled.

| Measurement | Result |
| --- | ---: |
| Events, including final database flush | 10,000 |
| Throughput | 1,218.12 events/s |
| Ingest latency p50 | 0.1018 ms |
| Ingest latency p95 | 0.2398 ms |
| SQLite batches | 79 |
| Writer health after flush | healthy |
| Process RSS growth | 11,673,600 bytes |
| Process CPU time | 2.7969 s |

This repeat is close to the prior synthetic result and is useful only as a local baseline. It still does not validate sustained load, real NIC traffic, burst handling at enterprise volume, multi-node scaling, retention cost, or any billion-event target.

## Workspace re-run — 2026-10-24

Command: `python scripts/benchmark_ingest.py --events 10000`

The benchmark pins imports to this checkout ahead of machine-level `PYTHONPATH` and emits `source_root`; this run reported `C:\Users\FEUCOM\BK-Security`. The sensitive-field filter was enabled. SQLite used the default 10-second flush deadline and completed with a healthy writer.

| Measurement | Result |
| --- | ---: |
| Events, including final database flush | 10,000 |
| Throughput | 802.95 events/s |
| Ingest latency p50 | 0.2205 ms |
| Ingest latency p95 | 0.6117 ms |
| SQLite batches | 79 |
| Writer health after flush | healthy |
| Process RSS growth | 11,984,896 bytes |
| Process CPU time | 8.7031 s |

This is a single synthetic local sample and is lower than the 2026-10-23 result; the difference is not attributed to a cause. The Phase 14 candidate of one billion events/day averages about 11,574 events/s, roughly 14.4 times this sample's rate. The candidate is a planning assumption, not an accepted SLO, and this run does not validate production capacity. Distributed ingestion, representative sustained load, burst handling, real NIC traffic, multi-node scaling and retention cost remain unvalidated.
