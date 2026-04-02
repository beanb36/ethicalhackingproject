from __future__ import annotations

import argparse

from chariot.monitor import run_monitor

# Parses command-line arguments and starts the process monitor.
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--interval",
        type=int,
        default=5,
        help="Seconds between monitor refreshes (default: 5)",
    )
    parser.add_argument(
        "--top",
        type=int,
        default=12,
        help="Number of top processes to display (default: 12)",
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="Run one scan and exit",
    )
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.interval < 1:
        parser.error("--interval must be >= 1")
    if args.top < 1:
        parser.error("--top must be >= 1")

    run_monitor(
        interval_seconds=args.interval,
        top_n=args.top,
        run_once=args.once,
        interactive=not args.once,
    )


if __name__ == "__main__":
    main()
