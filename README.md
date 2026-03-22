# 🛡️ The Evidence Protector
### Automated Log Integrity Monitor

> A lightweight forensic tool that scans system logs for suspicious time gaps — the digital fingerprint of a cover-up.

---

## 📸 What It Does

When a hacker breaks into a server, their first move is often to delete log entries that reveal their activity. But deleting entries from a continuous log creates an unavoidable **temporal gap** — a jump in time with no recorded events.

The Evidence Protector detects these gaps instantly, shows you exactly what happened before and after each missing window, and scores them by severity so analysts know where to look first.

---

## 🚀 Quick Start

### CLI Tool
```bash
# Basic scan
python integrity_check.py sample.log --threshold 60

# Export results
python integrity_check.py sample.log --threshold 60 --export json
python integrity_check.py sample.log --threshold 60 --export csv

# Use a config file
python integrity_check.py sample.log --config config.json

# Force a specific log format
python integrity_check.py sample.log --format syslog
```

### Web UI
```bash
pip install flask
python app.py
# Open http://localhost:5000
```

> The web UI requires an internet connection on first load to fetch fonts and Chart.js from CDN.

---

## 📁 Project Structure

```
evidence-protector/
├── integrity_check.py    # Core CLI tool (standard library only)
├── app.py                # Flask web interface
├── config.json           # Sample config file
├── sample.log            # Demo log — default format (with planted gaps)
├── sample_syslog.log     # Demo log — syslog format
├── sample_apache.log     # Demo log — Apache access log format
└── README.md             # This file
```

---

## 🖥️ CLI Output Example

```
╔══════════════════════════════════════════════╗
║       THE EVIDENCE PROTECTOR v1.0            ║
║       Automated Log Integrity Monitor        ║
╚══════════════════════════════════════════════╝

[ SCAN SUMMARY ]
  File Analyzed  : sample.log
  Format Detected: default
  Total Lines    : 75
  Parsed Lines   : 74
  Malformed Lines: 1
  Threshold      : 60 seconds

[ RISK SUMMARY ]
  CRITICAL : 1 gap(s)
  MEDIUM   : 3 gap(s)
  LOW      : 0 gap(s)

[ VISUAL TIMELINE ]

  20:00:00                                           21:50:00
  █████████████▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒░░░░░░░░░░░░░░░░░░███

  Legend: █ Normal  ▓ LOW  ▒ MEDIUM  ░ CRITICAL

               ^ GAP #1 (671s)
                     ^ GAP #2 (523s)
                          ^ GAP #3 (887s)
                                  ^ GAP #4 (2712s) ← CRITICAL

[ DETECTED GAPS + FORENSIC CONTEXT ]

  ▶ GAP #4 — CRITICAL
    Start    : 2008-11-09 21:00:18  (line 59)
    End      : 2008-11-09 21:45:30  (line 60)
    Duration : 2712 seconds (45m 12s)

    ┌─ LAST KNOWN ACTIVITY BEFORE GAP ──────────────────
    │  L57  NetworkManager: Device eth0: carrier lost
    │  L58  systemd: network.service: Deactivated
    │  L59  sshd: Received disconnect from 10.0.0.33
    │
    │  ⚠  2712s UNACCOUNTED  (45m 12s missing)
    │
    ├─ FIRST ACTIVITY AFTER GAP ─────────────────────────
    │  L60  kernel: EXT4-fs (sda1): mounted filesystem
    │  L61  sshd: Server listening on :: port 22
    │  L62  NetworkManager: new connection requested
    └────────────────────────────────────────────────────

[ ANALYST INSIGHTS ]
  Longest gap        : 2712s (45m 12s)
  Total missing time : 4793s (79m 53s)
  ⚠ CRITICAL gaps — immediate investigation recommended.

  Total Gaps Found: 4
```

---

## ⚙️ All CLI Options

| Flag | Description | Default |
|---|---|---|
| `logfile` | Path to log file | required |
| `--threshold N` | Gap size in seconds to flag | 60 |
| `--format` | `auto`, `default`, `syslog`, `apache`, `nginx`, `iso8601` | auto |
| `--export json\|csv` | Export gaps to file | none |
| `--output path` | Output file path for export | gaps.json / gaps.csv |
| `--config path` | Load settings from JSON config file | none |

---

## 📄 Config File

Instead of typing flags every time, use a `config.json`:

```json
{
  "threshold": 120,
  "format": "auto",
  "export": "json",
  "output": "gaps_report.json"
}
```

```bash
python integrity_check.py server.log --config config.json
```

CLI flags always override config file values.

---

## 📋 Supported Log Formats

| Format | Example Line |
|---|---|
| `default` | `081109 203615 148 INFO sshd: session opened` |
| `syslog` | `Nov  9 20:36:15 server sshd[1234]: session opened` |
| `apache` | `192.168.1.1 - - [09/Nov/2008:20:36:15 +0000] "GET /"` |
| `nginx` | `2008/11/09 20:36:15 [error] 1234: connect failed` |
| `iso8601` | `2008-11-09T20:36:15 INFO sshd: session opened` |

Auto-detect samples the first 50 lines and picks the best match automatically.

---

## 🔴 Severity Scoring

| Severity | Gap Duration | Action |
|---|---|---|
| **LOW** | < 5 minutes | Possibly routine — monitor |
| **MEDIUM** | 5 – 30 minutes | Suspicious — review recommended |
| **CRITICAL** | > 30 minutes | High priority — investigate immediately |

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────┐
│                integrity_check.py               │
├──────────────┬──────────────────────────────────┤
│ Module 0     │ CONFIG LAYER                     │
│              │ Loads config.json, merges with   │
│              │ CLI args (CLI always wins)        │
├──────────────┼──────────────────────────────────┤
│ Module 1     │ INPUT LAYER                      │
│              │ argparse — logfile, threshold,   │
│              │ format, export, config flags      │
├──────────────┼──────────────────────────────────┤
│ Module 2     │ PARSING LAYER                    │
│              │ Auto-detects format from 50-line  │
│              │ sample. Extracts timestamps via   │
│              │ regex + strptime. Returns None    │
│              │ on malformed lines — never crash  │
├──────────────┼──────────────────────────────────┤
│ Module 3     │ DETECTION ENGINE                 │
│              │ Single-pass read. Compares each  │
│              │ timestamp to previous. Flags      │
│              │ delta > threshold. Captures 3     │
│              │ context lines before + after gap  │
├──────────────┼──────────────────────────────────┤
│ Module 4     │ REPORTING LAYER                  │
│              │ ANSI-colored terminal output.     │
│              │ ASCII timeline. Forensic context  │
│              │ blocks. Analyst insights.         │
├──────────────┼──────────────────────────────────┤
│ Module 5     │ EXPORT LAYER                     │
│              │ JSON + CSV output for downstream  │
│              │ tooling or SIEM ingestion         │
└──────────────┴──────────────────────────────────┘
```

### Data Flow

```
Log File
  │
  ▼
[CONFIG]      ← merge config.json + CLI args
  │
  ▼
[INPUT]       ← validate file path, parse flags
  │
  ▼
[PARSING]     ← auto-detect format → extract timestamps line-by-line
  │              malformed lines → skipped, counted
  ▼
[DETECTION]   ← compare sequential deltas → flag gaps → score severity
  │              capture 3 context lines before/after each gap
  ▼
[REPORTING]   ← terminal output with color + ASCII timeline
  │
  ▼
[EXPORT]      ← optional JSON / CSV
```

---

## 🛡️ Error Handling

| Scenario | How It's Handled |
|---|---|
| File not found | Clear error message + exit |
| Permission denied | Clear error message + exit |
| Malformed log line | Silently skipped, counted in stats |
| Out-of-order timestamp | Treated as malformed, skipped |
| Empty file | Reports 0 gaps, no crash |
| Non-UTF8 characters | Replaced via `errors='replace'` |
| Invalid config JSON | Clear error message + exit |

**Design principle:** The tool must never crash mid-scan. An analyst running this on a compromised server under time pressure cannot afford unhandled exceptions.

---

## 🧠 Design Rationale

**Why line-by-line streaming?**
Log files can be gigabytes in size. Loading the entire file into memory would make the tool unusable on production servers. A generator-based approach is O(1) memory regardless of file size.

**Why standard library only?**
Security tools may need to run on air-gapped or locked-down systems where `pip install` is unavailable. Using only `argparse`, `datetime`, `re`, `json`, `csv`, and `os` means zero dependency friction.

**Why configurable threshold?**
Different environments have different baselines. A dev server may have 30-minute idle gaps that are normal. A financial transaction log should never have a 60-second gap. The `--threshold` flag lets analysts tune the tool to their context.

**Why severity scoring?**
Raw gap duration alone isn't enough. An analyst looking at 20 gaps needs to triage fast. Three buckets (LOW / MEDIUM / CRITICAL) give instant prioritisation without overcomplicating the model.

**Why forensic context lines?**
The most valuable signal isn't the gap itself — it's what happened immediately before and after it. Showing those lines directly in the report saves analysts from manually hunting through the file.

---

## ⚖️ Tradeoffs

| Decision | Tradeoff |
|---|---|
| Store all lines in dict for context | Rich forensic output vs. higher RAM on huge files |
| Single format per file | Fast and reliable vs. can't handle mid-file format changes |
| Simple severity buckets | Explainable and auditable vs. not ML-based |
| Flask for web UI | Lightweight vs. not production-hardened |
| Standard library only | Zero dependencies vs. no advanced parsing libraries |

---

## 📈 How to Scale

- **Huge files** — Replace the `all_lines` dict with a SQLite index — store byte offsets, seek on demand. O(1) RAM.
- **Multiple files** — Add a `--dir` flag, process each file through the pipeline, merge reports.
- **Real-time monitoring** — Swap the file reader for `tail -f` style streaming — keep a running `prev_ts` in memory, emit gaps live.
- **Enterprise** — The modular design means the Detection Engine can sit behind a task queue (Celery + Redis) to process 100 files in parallel without touching core logic.

---

## ➕ Adding a New Log Format

Add exactly 4 lines to the `LOG_FORMATS` list in `integrity_check.py`:

```python
{
    "name": "windows_event",
    "pattern": re.compile(r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})"),
    "parse": lambda m: datetime.strptime(m.group(1), "%Y-%m-%d %H:%M:%S")
}
```

Auto-detect, gap detection, reporting, and exports all work automatically. No other changes needed.

---

## ✅ Features

- [x] Severity scoring (LOW / MEDIUM / CRITICAL)
- [x] Summary insights (longest gap, total missing time)
- [x] JSON export (`--export json` via CLI or Export JSON button in Web UI)
- [x] CSV export (`--export csv` via CLI or Export CSV button in Web UI)
- [x] Visual ASCII timeline (CLI)
- [x] Visual interactive timeline (Web UI — clickable segments jump to gap details)
- [x] Anomaly Distribution scatter chart (Web UI — Chart.js, duration vs sequence)
- [x] Multi-format parsing with auto-detect
- [x] Config file support
- [x] Forensic context blocks (pre-gap log tail + post-gap log head)
- [x] Expandable gap rows in Web UI data table
- [x] Suspicious activity highlighting (`rm`, `COMMAND=`, `Accepted password`, etc.)
- [x] Malformed line tolerance — never crashes
- [x] Bloomberg terminal aesthetic (black + orange, IBM Plex Mono)

---

## 🌐 Web UI Overview

The web interface mirrors everything the CLI outputs but in an interactive browser UI with a Bloomberg terminal aesthetic — pure black background, orange accents, monospace typography.

**Panels:**

| Panel | Description |
|---|---|
| **Stat Bar** | Total gaps, Critical / Medium / Low counts, lines parsed, malformed count |
| **Execution Metadata** | Format detected, time range, threshold, total lines, Export CSV/JSON buttons |
| **Visual Timeline** | Interactive bar anchored to full log duration — click any gap segment to jump to its row |
| **Anomaly Distribution** | Chart.js scatter plot — each gap plotted by sequence number (X) vs duration in seconds (Y), colored by severity |
| **Discrepancy Ledger** | Sortable data table of all gaps — click any row to expand forensic context (pre-gap log tail + post-gap log head) |
| **System Intelligence** | Analyst recommendation based on highest severity found |

---

## 👤 Target Users

**Junior Security Analyst** — Runs CLI or Web UI, gets instant flagged gaps with context, investigates priority windows without manual log scanning.

**Security Lead** — Reviews exported JSON/CSV, checks severity summary, validates tool reliability before escalating findings.
