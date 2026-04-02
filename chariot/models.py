from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(slots=True)
class ProcessRecord:
    pid: int
    name: str
    username: str
    status: str
    cpu_percent: float
    memory_mb: float
    runtime_seconds: float
    thread_count: int
    open_file_count: int


@dataclass(slots=True)
class RiskResult:
    pid: int
    process_name: str
    score: int
    level: str
    reasons: list[str] = field(default_factory=list)
