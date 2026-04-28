from __future__ import annotations

import argparse
import hashlib
import tempfile
import threading
import time
from pathlib import Path


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--threads",
        type=int,
        default=90,
        help="Total threads to keep alive (default: 90)",
    )
    parser.add_argument(
        "--busy-threads",
        type=int,
        default=2,
        help="Threads that perform CPU-heavy work (default: 2)",
    )
    parser.add_argument(
        "--open-files",
        type=int,
        default=70,
        help="Number of log files to keep open (default: 70)",
    )
    parser.add_argument(
        "--log-interval",
        type=float,
        default=0.2,
        help="Seconds between log writes (default: 0.2)",
    )
    parser.add_argument(
        "--runtime-seconds",
        type=int,
        default=0,
        help="Auto-stop after N seconds (0 means run until Ctrl+C)",
    )
    return parser


def _cpu_worker(stop_event: threading.Event, worker_id: int) -> None:
    payload = f"worker-{worker_id}".encode("utf-8")
    data = payload
    while not stop_event.is_set():
        data = hashlib.sha256(data).digest()


def _idle_worker(stop_event: threading.Event) -> None:
    while not stop_event.is_set():
        time.sleep(1.0)


def _open_log_files(base_dir: Path, count: int) -> list:
    handles = []
    for idx in range(count):
        file_path = base_dir / f"event_{idx:03d}.log"
        handle = file_path.open("a", buffering=1, encoding="utf-8")
        handles.append(handle)
    return handles


def _log_writer(
    stop_event: threading.Event,
    handles: list,
    interval_seconds: float,
) -> None:
    counter = 0
    while not stop_event.is_set():
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        line = f"{timestamp} synthetic-event index={counter}\n"
        for handle in handles:
            handle.write(line)
        counter += 1
        time.sleep(interval_seconds)


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.threads < 1:
        parser.error("--threads must be >= 1")
    if args.busy_threads < 0:
        parser.error("--busy-threads must be >= 0")
    if args.busy_threads > args.threads:
        parser.error("--busy-threads cannot exceed --threads")
    if args.open_files < 1:
        parser.error("--open-files must be >= 1")
    if args.log_interval <= 0:
        parser.error("--log-interval must be > 0")
    if args.runtime_seconds < 0:
        parser.error("--runtime-seconds must be >= 0")

    temp_dir = Path(tempfile.mkdtemp(prefix="chariot_suspicious_sim_"))
    handles = _open_log_files(temp_dir, args.open_files)
    stop_event = threading.Event()
    threads: list[threading.Thread] = []

    for idx in range(args.busy_threads):
        thread = threading.Thread(
            target=_cpu_worker,
            args=(stop_event, idx),
            daemon=True,
            name=f"busy-worker-{idx}",
        )
        thread.start()
        threads.append(thread)

    idle_count = args.threads - args.busy_threads
    for idx in range(idle_count):
        thread = threading.Thread(
            target=_idle_worker,
            args=(stop_event,),
            daemon=True,
            name=f"idle-worker-{idx}",
        )
        thread.start()
        threads.append(thread)

    writer = threading.Thread(
        target=_log_writer,
        args=(stop_event, handles, args.log_interval),
        daemon=True,
        name="log-writer",
    )
    writer.start()
    threads.append(writer)

    print("Suspicious process simulator running.")
    print(f"PID markers: threads={args.threads}, open_files={args.open_files}, busy_threads={args.busy_threads}")
    print(f"Logs directory: {temp_dir}")
    if args.runtime_seconds == 0:
        print("Press Ctrl+C to stop.")
    else:
        print(f"Auto-stop in {args.runtime_seconds} seconds.")

    try:
        if args.runtime_seconds == 0:
            while True:
                time.sleep(1)
        else:
            deadline = time.time() + args.runtime_seconds
            while time.time() < deadline:
                time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        stop_event.set()
        for thread in threads:
            thread.join(timeout=0.2)
        for handle in handles:
            try:
                handle.close()
            except OSError:
                pass
        print("Simulator stopped.")


if __name__ == "__main__":
    main()