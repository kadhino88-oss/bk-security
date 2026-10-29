"""Synthetic local ingest benchmark; reports measurements, not a production SLA."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import statistics
import sys
import tempfile
import time
import uuid

# When invoked as ``python scripts/benchmark_ingest.py``, Python otherwise puts
# only ``scripts/`` before PYTHONPATH. Force this checkout to win over stale
# source copies referenced by a machine-level PYTHONPATH.
WORKSPACE_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(WORKSPACE_ROOT))

import psutil

from bk_security.core import SecurityCore
from bk_security.database import SecurityStore
from bk_security.events.models import SecurityEvent


def run_benchmark(database: Path, *, events: int, queue_size: int, batch_size: int, batch_window_ms: float) -> dict:
    try:
        store = SecurityStore(str(database), max_pending_writes=queue_size)
    except TypeError:  # Allows comparing against a pre-queue source snapshot.
        store = SecurityStore(str(database))
    store.write_batch_size = batch_size
    store.batch_window_seconds = batch_window_ms / 1000
    core = SecurityCore(store)
    process = psutil.Process()
    memory_before = process.memory_info().rss
    cpu_before = sum(process.cpu_times()[:2])
    latencies_ms: list[float] = []
    started = time.perf_counter()
    try:
        for index in range(events):
            event = SecurityEvent(
                event_type="network.dns",
                source="benchmark",
                host_id="benchmark-host",
                data={"domain": "ingest-benchmark.example", "sequence": index},
            )
            before = time.perf_counter()
            core.ingest(event)
            latencies_ms.append((time.perf_counter() - before) * 1000)
        flush = getattr(store, "flush", None)
        if flush:
            flush()
        elapsed = time.perf_counter() - started
        memory_after = process.memory_info().rss
        cpu_after = sum(process.cpu_times()[:2])
        status = getattr(store, "writer_status", {"healthy": True})
        return {
            "source_root": str(WORKSPACE_ROOT),
            "events": events,
            "event_rate_per_second_including_database_flush": round(events / elapsed, 2),
            "ingest_call_latency_ms_p50": round(statistics.median(latencies_ms), 4),
            "ingest_call_latency_ms_p95": round(sorted(latencies_ms)[int(0.95 * (len(latencies_ms) - 1))], 4),
            "batch_size": batch_size,
            "queue_capacity": queue_size,
            "batch_window_ms": batch_window_ms,
            "writer_healthy": status["healthy"],
            "database_batches": status.get("batches_written"),
            "process_rss_before_bytes": memory_before,
            "process_rss_after_bytes": memory_after,
            "process_rss_growth_bytes": memory_after - memory_before,
            "process_cpu_seconds": round(cpu_after - cpu_before, 4),
        }
    finally:
        close = getattr(store, "close", None)
        if close:
            close()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--events", type=int, default=10_000)
    parser.add_argument("--queue-size", type=int, default=4096)
    parser.add_argument("--batch-size", type=int, default=128)
    parser.add_argument("--batch-window-ms", type=float, default=10.0)
    args = parser.parse_args()
    if args.events < 1 or args.queue_size < 1 or args.batch_size < 1 or args.batch_window_ms < 0:
        parser.error("event, queue, and batch sizes must be positive; batch window cannot be negative")

    with tempfile.TemporaryDirectory(prefix="bk-security-ingest-benchmark-") as temporary:
        database = Path(temporary) / f"benchmark-{uuid.uuid4().hex}.sqlite3"
        result = run_benchmark(
            database,
            events=args.events,
            queue_size=args.queue_size,
            batch_size=args.batch_size,
            batch_window_ms=args.batch_window_ms,
        )
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
