# Ethical Hacking Project

This project is a keylogger detection prototype focused on contextual behavior, not static signatures.

## What it does right now

- Collects running process telemetry (CPU, runtime, thread count, open files)
- Scores process risk using context-based rules
- Sorts all running processes by risk score
- Explains why each risky process was flagged
- Prompts the user to terminate high-risk processes

## Risk model (version 0)

Processes gain score based on indicators such as:

- Suspicious process naming (keylog/hook/capture/spy keywords)
- Very long runtime (1+ hour and 6+ hours)
- Elevated thread count
- Elevated open file count
- Sudden spikes in open-file activity
- Elevated CPU usage

Then score is mapped to:

- Low
- Medium
- High
- Critical 

## Quick start

1. Create and activate a virtual environment
2. Install dependencies
3. Run monitor

```powershell
pip install -r requirements.txt
python main.py
```

## Test with a synthetic suspicious process

Use this helper process to trigger heuristic markers (high thread count, high open files, frequent log writes, and sustained CPU). It does not capture keyboard input.

```powershell
python suspicious_process_sim.py --threads 90 --busy-threads 2 --open-files 70
```

In another terminal, run:

```powershell
python main.py --top 20
```

To include the runtime heuristic as well, keep the simulator running for 1+ hour.

## Current files

- `main.py` : CLI entrypoint
- `keyguard/collector.py` : process telemetry collection
- `keyguard/risk.py` : risk scoring logic
- `keyguard/monitor.py` : monitoring loop, display, and terminate prompt
- `keyguard/models.py` : shared data models

## Notes

- False positives are expected
- On Windows, terminating protected/system processes is restricted
  - I can't seem to kill Microsoft Edge
- Some process fields may be inaccessible


## Suggested next steps

- Add keyboard API call telemetry for stronger keylogger detection
- Do more than just context checking. Adding in Signature data on top of context checks.
- Add historical trend reports
- Add desktop toast notifications / GUI
- Train a baseline model per machine to reduce false positives


## Feedback from Professor Sarker

- Categorzed data
- If taken code write source
- Reasoning behind scores


