from __future__ import annotations

from .models import ProcessRecord, RiskResult

SUSPICIOUS_KEYWORDS = (
    "keylog",
    "keyboard",
    "hook",
    "capture",
    "inject",
    "spy",
    "logger",
)

KNOWN_SAFE_NAMES = {
    "system",
    "idle",
    "csrss.exe",
    "wininit.exe",
    "services.exe",
    "lsass.exe",
    "svchost.exe",
    "explorer.exe",
}


def _risk_level(score: int) -> str:
    if score >= 70:
        return "critical"
    if score >= 45:
        return "high"
    if score >= 20:
        return "medium"
    return "low"


def score_process(record: ProcessRecord, previous_open_file_count: int | None) -> RiskResult:
    score = 0
    reasons: list[str] = []

    lowered_name = record.name.lower()
    if any(keyword in lowered_name for keyword in SUSPICIOUS_KEYWORDS):
        score += 35
        reasons.append("Name contains suspicious keyboard/logger keyword")

    if record.runtime_seconds >= 6 * 3600:
        score += 25
        reasons.append("Long-running process (6+ hours)")
    elif record.runtime_seconds >= 3600:
        score += 10
        reasons.append("Long-running process (1+ hour)")

    if record.thread_count >= 80:
        score += 15
        reasons.append("Very high thread count")
    elif record.thread_count >= 40:
        score += 8
        reasons.append("Elevated thread count")

    if record.open_file_count >= 50:
        score += 20
        reasons.append("High number of open files")
    elif record.open_file_count >= 15:
        score += 10
        reasons.append("Elevated file activity")

    if previous_open_file_count is not None:
        spike = record.open_file_count - previous_open_file_count
        if spike >= 20:
            score += 12
            reasons.append("Open-file activity spiked recently")
        elif spike >= 10:
            score += 6
            reasons.append("Open-file activity increased")

    if record.cpu_percent >= 60:
        score += 12
        reasons.append("High CPU usage")
    elif record.cpu_percent >= 30:
        score += 6
        reasons.append("Elevated CPU usage")

    if lowered_name in KNOWN_SAFE_NAMES:
        score = max(0, score - 12)
        reasons.append("Known common system process (risk reduced)")

    level = _risk_level(score)
    return RiskResult(
        pid=record.pid,
        process_name=record.name,
        score=score,
        level=level,
        reasons=reasons or ["No strong indicators observed"],
    )
