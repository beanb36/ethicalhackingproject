from __future__ import annotations

import time
from typing import Iterable

import psutil

from .models import ProcessRecord


def _safe_len_open_files(proc: psutil.Process) -> int:
    try:
        files = proc.open_files()
        return len(files)
    except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess):
        return 0


def collect_process_records() -> list[ProcessRecord]:
    # Collect lightweight process telemetry for risk evaluation.
    now = time.time()
    records: list[ProcessRecord] = []

    attrs: Iterable[str] = (
        "pid",
        "name",
        "username",
        "status",
        "cpu_percent",
        "memory_info",
        "create_time",
        "num_threads",
    )

    for proc in psutil.process_iter(attrs=attrs):
        try:
            info = proc.info
            name = info.get("name") or "<unknown>"
            username = info.get("username") or "<unknown>"
            status = info.get("status") or "unknown"
            cpu = float(info.get("cpu_percent") or 0.0)
            memory_info = info.get("memory_info")
            memory_mb = (memory_info.rss / (1024 * 1024)) if memory_info else 0.0
            create_time = float(info.get("create_time") or now)
            runtime_seconds = max(0.0, now - create_time)
            thread_count = int(info.get("num_threads") or 0)
            open_file_count = _safe_len_open_files(proc)

            records.append(
                ProcessRecord(
                    pid=int(info["pid"]),
                    name=name,
                    username=username,
                    status=status,
                    cpu_percent=cpu,
                    memory_mb=memory_mb,
                    runtime_seconds=runtime_seconds,
                    thread_count=thread_count,
                    open_file_count=open_file_count,
                )
            )
        except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess, KeyError):
            continue

    return records
