from __future__ import annotations

import os
import time
from dataclasses import dataclass

import psutil

from .collector import collect_process_records
from .models import ProcessRecord, RiskResult
from .risk import score_process

CRITICAL_SYSTEM_PROCESSES = {
    "system",
    "smss.exe",
    "csrss.exe",
    "wininit.exe",
    "services.exe",
    "lsass.exe",
    "winlogon.exe",
}


@dataclass(slots=True)
class ProcessState:
    first_seen: float
    last_seen: float
    open_file_count: int

# Main monitoring logic for Chariot. Evaluates process risk and offers interactive termination for high-risk processes.
class ProcessMonitor:
    def __init__(self) -> None:
        self._history: dict[int, ProcessState] = {}

    def evaluate(self) -> list[tuple[ProcessRecord, RiskResult]]:
        now = time.time()
        records = collect_process_records()
        active_pids = {r.pid for r in records}

        assessments: list[tuple[ProcessRecord, RiskResult]] = []
        for record in records:
            state = self._history.get(record.pid)
            previous_open_count = state.open_file_count if state else None

            result = score_process(record, previous_open_count)
            assessments.append((record, result))

            if state:
                state.last_seen = now
                state.open_file_count = record.open_file_count
            else:
                self._history[record.pid] = ProcessState(
                    first_seen=now,
                    last_seen=now,
                    open_file_count=record.open_file_count,
                )

        # Remove stale process state.
        stale = [pid for pid in self._history if pid not in active_pids]
        for pid in stale:
            del self._history[pid]

        assessments.sort(key=lambda row: row[1].score, reverse=True)
        return assessments


def _clear_screen() -> None:
    os.system("cls" if os.name == "nt" else "clear")


def _format_runtime(seconds: float) -> str:
    sec = int(seconds)
    h, rem = divmod(sec, 3600)
    m, s = divmod(rem, 60)
    return f"{h:02d}:{m:02d}:{s:02d}"


def _print_table(assessments: list[tuple[ProcessRecord, RiskResult]], top_n: int) -> None:
    print("\nTop Risky Processes")
    print("=" * 95)
    print(f"{'PID':>7}  {'Process':<25} {'Risk':<9} {'Score':>5} {'Runtime':>10} {'CPU%':>7} {'OpenFiles':>10}")
    print("-" * 95)

    for record, result in assessments[:top_n]:
        print(
            f"{record.pid:>7}  "
            f"{record.name[:25]:<25} "
            f"{result.level:<9} "
            f"{result.score:>5} "
            f"{_format_runtime(record.runtime_seconds):>10} "
            f"{record.cpu_percent:>7.1f} "
            f"{record.open_file_count:>10}"
        )

    print("=" * 95)


def _should_offer_termination(result: RiskResult) -> bool:
    return result.level in {"high", "critical"}


def _is_protected_process(name: str, pid: int) -> bool:
    if pid <= 4:
        return True
    return name.lower() in CRITICAL_SYSTEM_PROCESSES


def _terminate_process(pid: int) -> bool:
    try:
        proc = psutil.Process(pid)
        proc.terminate()
        proc.wait(timeout=3)
        return True
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.TimeoutExpired):
        return False


def run_monitor(
    interval_seconds: int = 5,
    top_n: int = 12,
    run_once: bool = False,
    interactive: bool = True,
) -> None:
    monitor = ProcessMonitor()

    while True:
        _clear_screen()
        assessments = monitor.evaluate()
        _print_table(assessments, top_n=top_n)

        high_risk = [(r, rr) for r, rr in assessments if _should_offer_termination(rr)]
        if high_risk:
            print("\nThreat Alerts")
            for record, result in high_risk[:5]:
                print(f"- PID {record.pid} [{record.name}] -> {result.level.upper()} ({result.score})")
                print(f"  Reason: {result.reasons[0]}")

            candidate = high_risk[0]
            rec, res = candidate
            if interactive and not _is_protected_process(rec.name, rec.pid):
                choice = input(
                    f"\nTerminate PID {rec.pid} ({rec.name})? "
                    f"[{res.level.upper()} risk] (y/N): "
                ).strip().lower()
                if choice == "y":
                    stopped = _terminate_process(rec.pid)
                    print("Process terminated." if stopped else "Unable to terminate process.")
                    time.sleep(2)
            elif _is_protected_process(rec.name, rec.pid):
                print("\nTop high-risk process is protected system process; skipping termination prompt.")

        if run_once:
            break

        print(f"\nRefreshing in {interval_seconds} seconds. Press Ctrl+C to stop.")
        try:
            time.sleep(interval_seconds)
        except KeyboardInterrupt:
            print("\nMonitoring stopped.")
            break
