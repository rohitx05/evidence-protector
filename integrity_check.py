#!/usr/bin/env python3
"""
integrity_check.py — The Evidence Protector
Automated Log Integrity Monitor

Usage:
    python integrity_check.py logfile.log
    python integrity_check.py logfile.log --threshold 60
    python integrity_check.py logfile.log --threshold 60 --export json
    python integrity_check.py logfile.log --threshold 60 --export csv
    python integrity_check.py logfile.log --config config.json
    python integrity_check.py logfile.log --format syslog
"""

import argparse
import sys
import json
import csv
import re
import os
from datetime import datetime

# ─────────────────────────────────────────────
# MODULE 0: CONFIG LAYER
# ─────────────────────────────────────────────

DEFAULT_CONFIG = {
    "threshold": 60,
    "export": None,
    "output": None,
    "format": "auto"
}

def load_config(config_path):
    if not config_path:
        return DEFAULT_CONFIG.copy()
    if not os.path.exists(config_path):
        print(f"[ERROR] Config file not found: {config_path}")
        sys.exit(1)
    try:
        with open(config_path, "r") as f:
            user_cfg = json.load(f)
        cfg = DEFAULT_CONFIG.copy()
        cfg.update(user_cfg)
        return cfg
    except json.JSONDecodeError as e:
        print(f"[ERROR] Invalid JSON in config file: {e}")
        sys.exit(1)


# ─────────────────────────────────────────────
# MODULE 1: INPUT LAYER
# ─────────────────────────────────────────────

def parse_arguments():
    parser = argparse.ArgumentParser(
        description="The Evidence Protector — Detect suspicious time gaps in log files.",
        epilog="Example: python integrity_check.py server.log --threshold 60"
    )
    parser.add_argument("logfile", help="Path to the log file to analyze")
    parser.add_argument("--threshold", type=int, default=None,
                        help="Gap threshold in seconds (default: 60)")
    parser.add_argument("--export", choices=["json", "csv"],
                        help="Export gaps to JSON or CSV format")
    parser.add_argument("--output", help="Output file path for export")
    parser.add_argument("--config", help="Path to JSON config file")
    parser.add_argument("--format",
                        choices=["auto", "default", "syslog", "apache", "iso8601", "nginx"],
                        default=None, help="Log format (default: auto-detect)")
    return parser.parse_args()


def resolve_config(args):
    cfg = load_config(args.config)
    if args.threshold is not None:
        cfg["threshold"] = args.threshold
    if args.export is not None:
        cfg["export"] = args.export
    if args.output is not None:
        cfg["output"] = args.output
    if args.format is not None:
        cfg["format"] = args.format
    return cfg


# ─────────────────────────────────────────────
# MODULE 2: PARSING LAYER — MULTI-FORMAT
# ─────────────────────────────────────────────

def _parse_syslog(raw):
    try:
        year = datetime.now().year
        return datetime.strptime(f"{year} {raw.strip()}", "%Y %b %d %H:%M:%S")
    except ValueError:
        return None


LOG_FORMATS = [
    {
        "name": "default",
        "pattern": re.compile(r"^(\d{6})\s+(\d{6})\b"),
        "parse": lambda m: datetime.strptime(m.group(1) + " " + m.group(2), "%y%m%d %H%M%S")
    },
    {
        "name": "syslog",
        "pattern": re.compile(r"^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"),
        "parse": lambda m: _parse_syslog(m.group(1))
    },
    {
        "name": "apache",
        "pattern": re.compile(r"\[(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2})\s[+-]\d{4}\]"),
        "parse": lambda m: datetime.strptime(m.group(1), "%d/%b/%Y:%H:%M:%S")
    },
    {
        "name": "nginx",
        "pattern": re.compile(r"^(\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})"),
        "parse": lambda m: datetime.strptime(m.group(1), "%Y/%m/%d %H:%M:%S")
    },
    {
        "name": "iso8601",
        "pattern": re.compile(r"(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})"),
        "parse": lambda m: datetime.strptime(m.group(1).replace("T", " "), "%Y-%m-%d %H:%M:%S")
    },
]


def detect_format(filepath, sample_lines=50):
    scores = {fmt["name"]: 0 for fmt in LOG_FORMATS}
    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            for i, line in enumerate(f):
                if i >= sample_lines:
                    break
                for fmt in LOG_FORMATS:
                    if fmt["pattern"].search(line):
                        scores[fmt["name"]] += 1
    except (FileNotFoundError, PermissionError):
        pass
    best = max(scores, key=scores.get)
    return best if scores[best] > 0 else "default"


def get_format(name):
    for fmt in LOG_FORMATS:
        if fmt["name"] == name:
            return fmt
    return LOG_FORMATS[0]


def extract_timestamp(line, fmt):
    line = line.strip()
    if not line:
        return None
    try:
        m = fmt["pattern"].search(line)
        if not m:
            return None
        return fmt["parse"](m)
    except (ValueError, IndexError, AttributeError):
        return None


# ─────────────────────────────────────────────
# MODULE 3: DETECTION ENGINE
# ─────────────────────────────────────────────

CONTEXT_LINES = 3  # log lines shown before/after each gap

def classify_severity(duration_seconds):
    if duration_seconds < 300:
        return "LOW"
    elif duration_seconds < 1800:
        return "MEDIUM"
    else:
        return "CRITICAL"


def detect_gaps(filepath, threshold_seconds, format_name="auto"):
    """
    Core detection engine.
    Single-pass read: tracks timestamps, detects gaps, captures
    surrounding log context lines for forensic investigation.
    """
    if format_name == "auto":
        format_name = detect_format(filepath)
    fmt = get_format(format_name)

    gaps = []
    prev_ts = None
    prev_line = None
    first_ts = None
    last_ts = None
    total_lines = 0
    parsed_lines = 0
    malformed_lines = 0

    # Rolling buffer: keeps last N raw lines for "before gap" context
    line_buffer = []   # list of (line_num, raw_text)
    all_lines = {}     # line_num -> raw_text (for "after gap" context lookup)

    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            for line_num, line in enumerate(f, start=1):
                total_lines += 1
                raw = line.rstrip()
                all_lines[line_num] = raw

                ts = extract_timestamp(line, fmt)

                if ts is None:
                    malformed_lines += 1
                    line_buffer.append((line_num, raw))
                    if len(line_buffer) > CONTEXT_LINES + 1:
                        line_buffer.pop(0)
                    continue

                parsed_lines += 1
                if first_ts is None:
                    first_ts = ts
                last_ts = ts

                if prev_ts is not None:
                    delta = (ts - prev_ts).total_seconds()
                    if delta < 0:
                        malformed_lines += 1
                    elif delta > threshold_seconds:
                        before_ctx = list(line_buffer[-CONTEXT_LINES:])
                        gaps.append({
                            "gap_number":       len(gaps) + 1,
                            "start_time":       prev_ts.strftime("%Y-%m-%d %H:%M:%S"),
                            "end_time":         ts.strftime("%Y-%m-%d %H:%M:%S"),
                            "start_line":       prev_line,
                            "end_line":         line_num,
                            "duration_seconds": int(delta),
                            "severity":         classify_severity(int(delta)),
                            "before_context":   before_ctx,
                            "after_line_num":   line_num,
                        })

                # Update rolling buffer
                line_buffer.append((line_num, raw))
                if len(line_buffer) > CONTEXT_LINES + 1:
                    line_buffer.pop(0)

                prev_ts = ts
                prev_line = line_num

    except FileNotFoundError:
        print(f"[ERROR] File not found: {filepath}")
        sys.exit(1)
    except PermissionError:
        print(f"[ERROR] Permission denied: {filepath}")
        sys.exit(1)

    # Attach "after" context using the line index
    for gap in gaps:
        start = gap["after_line_num"]
        gap["after_context"] = [
            (ln, all_lines[ln])
            for ln in range(start, start + CONTEXT_LINES)
            if ln in all_lines
        ]

    stats = {
        "total_lines":    total_lines,
        "parsed_lines":   parsed_lines,
        "malformed_lines": malformed_lines,
        "threshold_seconds": threshold_seconds,
        "format_detected": format_name,
        "log_start": first_ts.strftime("%Y-%m-%d %H:%M:%S") if first_ts else None,
        "log_end":   last_ts.strftime("%Y-%m-%d %H:%M:%S")  if last_ts  else None,
        "total_gaps":     len(gaps),
        "critical_gaps":  sum(1 for g in gaps if g["severity"] == "CRITICAL"),
        "medium_gaps":    sum(1 for g in gaps if g["severity"] == "MEDIUM"),
        "low_gaps":       sum(1 for g in gaps if g["severity"] == "LOW"),
    }

    return gaps, stats


# ─────────────────────────────────────────────
# MODULE 4: REPORTING LAYER
# ─────────────────────────────────────────────

SEVERITY_COLORS = {
    "CRITICAL": "\033[91m",
    "MEDIUM":   "\033[93m",
    "LOW":      "\033[94m",
    "RESET":    "\033[0m",
    "BOLD":     "\033[1m",
    "GREEN":    "\033[92m",
    "CYAN":     "\033[96m",
    "DIM":      "\033[2m",
}

def colorize(text, color_key):
    return f"{SEVERITY_COLORS.get(color_key, '')}{text}{SEVERITY_COLORS['RESET']}"


def print_banner():
    print(colorize("""
╔══════════════════════════════════════════════╗
║       THE EVIDENCE PROTECTOR v1.0            ║
║       Automated Log Integrity Monitor        ║
╚══════════════════════════════════════════════╝
""", "CYAN"))


def print_ascii_timeline(gaps, stats):
    """
    Render an ASCII timeline bar anchored to the FULL log duration
    (first entry → last entry), so normal green sections are visible
    proportionally to gaps.
    """
    if not gaps:
        return

    WIDTH = 60

    # Use full log span — not just gap boundaries
    t_min = datetime.strptime(stats["log_start"], "%Y-%m-%d %H:%M:%S")
    t_max = datetime.strptime(stats["log_end"],   "%Y-%m-%d %H:%M:%S")
    total_span = (t_max - t_min).total_seconds()
    if total_span == 0:
        return

    SEV_CHAR = {"CRITICAL": "░", "MEDIUM": "▒", "LOW": "▓"}

    bar     = ["█"] * WIDTH
    bar_sev = [None] * WIDTH

    for g in gaps:
        gs = datetime.strptime(g["start_time"], "%Y-%m-%d %H:%M:%S")
        ge = datetime.strptime(g["end_time"],   "%Y-%m-%d %H:%M:%S")
        slot_s = int(((gs - t_min).total_seconds() / total_span) * (WIDTH - 1))
        slot_e = int(((ge - t_min).total_seconds() / total_span) * (WIDTH - 1))
        slot_e = max(slot_e, slot_s + 1)
        for i in range(slot_s, min(slot_e + 1, WIDTH)):
            bar[i] = SEV_CHAR[g["severity"]]
            bar_sev[i] = g["severity"]

    print(colorize("[ VISUAL TIMELINE ]", "BOLD"))
    print()
    print("  " + t_min.strftime("%H:%M:%S") + " " * (WIDTH - 17) + t_max.strftime("%H:%M:%S"))

    rendered = "  "
    for ch, sev in zip(bar, bar_sev):
        rendered += colorize(ch, sev if sev else "GREEN")
    print(rendered)

    print()
    print("  Legend: " +
          colorize("█ Normal", "GREEN") + "  " +
          colorize("▓ LOW", "LOW") + "  " +
          colorize("▒ MEDIUM", "MEDIUM") + "  " +
          colorize("░ CRITICAL", "CRITICAL"))
    print()

    for g in gaps:
        gs = datetime.strptime(g["start_time"], "%Y-%m-%d %H:%M:%S")
        slot_s = int(((gs - t_min).total_seconds() / total_span) * (WIDTH - 1))
        marker = " " * (slot_s + 2) + f"^ GAP #{g['gap_number']} ({g['duration_seconds']}s)"
        print(colorize(marker, g["severity"]))
    print()


def print_context_block(gap):
    """
    Print the log lines immediately before and after a gap.
    This is the forensic 'what was happening around the gap' view.
    """
    sev = gap["severity"]
    print(colorize("    ┌─ LAST KNOWN ACTIVITY BEFORE GAP ─────────────────", sev))
    for ln, text in gap.get("before_context", []):
        truncated = text[:100] + ("…" if len(text) > 100 else "")
        print(colorize(f"    │ ", sev) + colorize(f"L{ln:>5} ", "DIM") + truncated)
    print(colorize(f"    │", sev))
    print(colorize(f"    │  ⚠  {gap['duration_seconds']}s UNACCOUNTED  "
                   f"({gap['duration_seconds']//60}m {gap['duration_seconds']%60}s missing)", sev))
    print(colorize(f"    │", sev))
    print(colorize("    ├─ FIRST ACTIVITY AFTER GAP ──────────────────────", sev))
    for ln, text in gap.get("after_context", []):
        truncated = text[:100] + ("…" if len(text) > 100 else "")
        print(colorize(f"    │ ", sev) + colorize(f"L{ln:>5} ", "DIM") + truncated)
    print(colorize("    └───────────────────────────────────────────────────", sev))
    print()


def print_report(gaps, stats, filepath):
    """Print the full forensic report: summary, timeline, gaps with context, insights."""
    print_banner()

    print(colorize("[ SCAN SUMMARY ]", "BOLD"))
    print(f"  File Analyzed  : {filepath}")
    print(f"  Format Detected: {stats['format_detected']}")
    print(f"  Total Lines    : {stats['total_lines']}")
    print(f"  Parsed Lines   : {stats['parsed_lines']}")
    print(f"  Malformed Lines: {stats['malformed_lines']}")
    print(f"  Threshold      : {stats['threshold_seconds']} seconds")
    print()

    if stats["total_gaps"] == 0:
        print(colorize("  ✓ No suspicious gaps detected. Log appears intact.\n", "GREEN"))
        return

    print(colorize("[ RISK SUMMARY ]", "BOLD"))
    print(colorize(f"  CRITICAL : {stats['critical_gaps']} gap(s)", "CRITICAL"))
    print(colorize(f"  MEDIUM   : {stats['medium_gaps']} gap(s)", "MEDIUM"))
    print(colorize(f"  LOW      : {stats['low_gaps']} gap(s)", "LOW"))
    print()

    # ASCII timeline
    print_ascii_timeline(gaps, stats)

    # Detailed gaps with context
    print(colorize("[ DETECTED GAPS + FORENSIC CONTEXT ]", "BOLD"))
    print()
    for gap in gaps:
        sev = gap["severity"]
        print(colorize(f"  ▶ GAP #{gap['gap_number']} — {sev}", sev))
        print(f"    Start     : {gap['start_time']}  (line {gap['start_line']})")
        print(f"    End       : {gap['end_time']}  (line {gap['end_line']})")
        print(f"    Duration  : {gap['duration_seconds']} seconds "
              f"({gap['duration_seconds'] // 60}m {gap['duration_seconds'] % 60}s)")
        print()
        print_context_block(gap)

    print(colorize("[ ANALYST INSIGHTS ]", "BOLD"))
    longest = max(gaps, key=lambda g: g["duration_seconds"])
    total_gap_time = sum(g["duration_seconds"] for g in gaps)
    print(f"  Longest gap        : {longest['duration_seconds']}s between "
          f"{longest['start_time']} → {longest['end_time']}")
    print(f"  Total missing time : {total_gap_time}s "
          f"({total_gap_time // 60}m {total_gap_time % 60}s)")

    if stats["critical_gaps"] > 0:
        print(colorize("  ⚠ CRITICAL gaps — immediate investigation recommended.", "CRITICAL"))
    elif stats["medium_gaps"] > 0:
        print(colorize("  ⚠ MEDIUM gaps — review recommended.", "MEDIUM"))
    else:
        print(colorize("  ℹ Only LOW severity gaps — likely routine activity.", "LOW"))

    print(f"\n  Total Gaps Found: {stats['total_gaps']}\n")


# ─────────────────────────────────────────────
# MODULE 5: EXPORT LAYER
# ─────────────────────────────────────────────

def export_json(gaps, stats, output_path):
    # Strip context from export (keep it clean for downstream tools)
    clean_gaps = [
        {k: v for k, v in g.items()
         if k not in ("before_context", "after_context", "after_line_num")}
        for g in gaps
    ]
    payload = {"summary": stats, "gaps": clean_gaps}
    with open(output_path, "w") as f:
        json.dump(payload, f, indent=2)
    print(colorize(f"  ✓ JSON report saved to: {output_path}", "GREEN"))


def export_csv(gaps, output_path):
    if not gaps:
        print("  No gaps to export.")
        return
    fieldnames = ["gap_number", "start_time", "end_time", "start_line",
                  "end_line", "duration_seconds", "severity"]
    with open(output_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for g in gaps:
            writer.writerow({k: g[k] for k in fieldnames})
    print(colorize(f"  ✓ CSV report saved to: {output_path}", "GREEN"))


# ─────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────

def main():
    args = parse_arguments()
    cfg = resolve_config(args)

    gaps, stats = detect_gaps(args.logfile, cfg["threshold"], cfg["format"])
    print_report(gaps, stats, args.logfile)

    if cfg["export"]:
        if cfg["export"] == "json":
            export_json(gaps, stats, cfg["output"] or "gaps.json")
        elif cfg["export"] == "csv":
            export_csv(gaps, cfg["output"] or "gaps.csv")


if __name__ == "__main__":
    main()
