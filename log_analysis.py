"""
Linux Log File Analyzer
=======================
Parses Linux syslog files to detect suspicious authentication activity,
brute force patterns, and unknown user enumeration attempts.

Author: Rohan Chowdhury
Usage: python log_analysis.py [--log Linux_2k.log] [--threshold 5]
"""

from __future__ import annotations

import re
import csv
import argparse
from collections import defaultdict


# ─── Constants ────────────────────────────────────────────────────────────────

BRUTE_FORCE_THRESHOLD = 5  # Failed attempts from same IP to trigger alert

LOG_PATTERNS = {
    "Failed Login":      re.compile(r"Failed password for (?:invalid user )?(\S+) from ([\d\.]+|\S+) port \d+"),
    "Auth Failure":      re.compile(r"authentication failure;.*?rhost=([\d\.]+|\S+?)(?:\s+user=(\S+))?$"),
    "Unknown User":      re.compile(r"check pass; user unknown"),
    "Invalid User":      re.compile(r"invalid user (\S+)"),
    "Session Opened":    re.compile(r"session opened for user (\S+)"),
    "Session Closed":    re.compile(r"session closed for user (\S+)"),
    "FTP Connection":    re.compile(r"ftpd\[\d+\]: connection from ([\d\.]+)"),
    "Logrotate Alert":   re.compile(r"logrotate: ALERT"),
}

TIMESTAMP_PATTERN = re.compile(
    r"^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+)\[(\d+)\]:\s+(.*)"
)


# ─── Parsing ──────────────────────────────────────────────────────────────────

def parse_log_line(line: str, line_number: int) -> dict | None:
    """
    Parse a single syslog line into structured fields.
    Returns None if the line doesn't match the expected format.
    """
    match = TIMESTAMP_PATTERN.match(line.strip())
    if not match:
        return None

    timestamp_str, hostname, service, pid, message = match.groups()

    entry = {
        "line_number": line_number,
        "timestamp":   timestamp_str,
        "hostname":    hostname,
        "service":     service,
        "pid":         pid,
        "message":     message,
        "event_type":  None,
        "source_ip":   None,
        "username":    None,
        "severity":    "INFO",
        "raw":         line.strip(),
    }

    # Match against known patterns
    for event_type, pattern in LOG_PATTERNS.items():
        m = pattern.search(message)
        if m:
            entry["event_type"] = event_type
            groups = m.groups()

            if event_type == "Failed Login":
                entry["username"]   = groups[0] if groups[0] else None
                entry["source_ip"]  = groups[1] if len(groups) > 1 else None
                entry["severity"]   = "HIGH"

            elif event_type == "Auth Failure":
                entry["source_ip"]  = groups[0].rstrip() if groups[0] else None
                entry["username"]   = groups[1] if len(groups) > 1 and groups[1] else None
                entry["severity"]   = "HIGH"

            elif event_type in ("Unknown User", "Invalid User"):
                entry["username"]   = groups[0] if groups else None
                entry["severity"]   = "MEDIUM"

            elif event_type in ("Session Opened", "Session Closed"):
                entry["username"]   = groups[0] if groups else None
                entry["severity"]   = "INFO"

            elif event_type == "FTP Connection":
                entry["source_ip"]  = groups[0] if groups else None
                entry["severity"]   = "MEDIUM"

            elif event_type == "Logrotate Alert":
                entry["severity"]   = "LOW"

            break  # First match wins

    return entry if entry["event_type"] else None


def parse_log_file(filepath: str) -> list[dict]:
    """Read and parse all lines from a log file."""
    parsed = []
    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        for i, line in enumerate(f, start=1):
            entry = parse_log_line(line, i)
            if entry:
                parsed.append(entry)
    return parsed


# ─── Detection ────────────────────────────────────────────────────────────────

def detect_brute_force(entries: list[dict], threshold: int = BRUTE_FORCE_THRESHOLD) -> list[dict]:
    """
    Flag IPs that exceed the failure threshold — likely brute force attempts.
    Returns a list of alert dicts sorted by attempt count descending.
    """
    ip_failures = defaultdict(list)

    for entry in entries:
        if entry["event_type"] in ("Auth Failure", "Failed Login") and entry["source_ip"]:
            ip_failures[entry["source_ip"]].append(entry["timestamp"])

    alerts = []
    for ip, timestamps in ip_failures.items():
        if len(timestamps) >= threshold:
            alerts.append({
                "source_ip":     ip,
                "attempt_count": len(timestamps),
                "first_seen":    timestamps[0],
                "last_seen":     timestamps[-1],
                "severity":      "CRITICAL" if len(timestamps) >= 20 else "HIGH",
            })

    return sorted(alerts, key=lambda x: x["attempt_count"], reverse=True)


def detect_user_enumeration(entries: list[dict]) -> list[dict]:
    """Identify usernames targeted in unknown/invalid user attempts."""
    targets = defaultdict(int)
    for entry in entries:
        if entry["event_type"] in ("Unknown User", "Invalid User") and entry["username"]:
            targets[entry["username"]] += 1

    return sorted(
        [{"username": u, "attempt_count": c} for u, c in targets.items()],
        key=lambda x: x["attempt_count"],
        reverse=True
    )


# ─── Reporting ────────────────────────────────────────────────────────────────

def print_summary(entries: list[dict], brute_force: list[dict], enumeration: list[dict]) -> None:
    """Print a formatted summary report to stdout."""

    # Event type counts
    type_counts = defaultdict(int)
    severity_counts = defaultdict(int)
    for e in entries:
        type_counts[e["event_type"]] += 1
        severity_counts[e["severity"]] += 1

    print("=" * 60)
    print("       LINUX LOG ANALYSIS — THREAT SUMMARY REPORT")
    print("=" * 60)

    print(f"\n{'TOTAL PARSED EVENTS':<35} {len(entries)}")
    print(f"{'─' * 45}")

    print("\n[EVENT BREAKDOWN]")
    for etype, count in sorted(type_counts.items(), key=lambda x: x[1], reverse=True):
        print(f"  {etype:<30} {count:>5}")

    print("\n[SEVERITY BREAKDOWN]")
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        count = severity_counts.get(sev, 0)
        if count:
            print(f"  {sev:<30} {count:>5}")

    print(f"\n{'─' * 45}")
    print(f"[BRUTE FORCE ALERTS]  ({len(brute_force)} IPs flagged)")
    if brute_force:
        print(f"  {'IP':<45} {'Attempts':>8}  {'Severity'}")
        print(f"  {'─'*45} {'─'*8}  {'─'*8}")
        for alert in brute_force[:10]:  # Top 10
            print(f"  {alert['source_ip']:<45} {alert['attempt_count']:>8}  {alert['severity']}")
    else:
        print("  No brute force activity detected.")

    print(f"\n[USER ENUMERATION TARGETS]  (top 10)")
    if enumeration:
        print(f"  {'Username':<25} {'Attempts':>8}")
        print(f"  {'─'*25} {'─'*8}")
        for item in enumeration[:10]:
            print(f"  {item['username']:<25} {item['attempt_count']:>8}")
    else:
        print("  No enumeration attempts detected.")

    print("\n" + "=" * 60)


def export_csv(entries: list[dict], brute_force: list[dict], enumeration: list[dict]) -> None:
    """Export results to structured CSV files."""

    # All suspicious events
    with open("suspicious_logs.csv", "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "line_number", "timestamp", "hostname", "service",
            "event_type", "severity", "source_ip", "username", "raw"
        ])
        writer.writeheader()
        for e in entries:
            writer.writerow({k: e[k] for k in writer.fieldnames})
    print("  [+] suspicious_logs.csv")

    # Brute force alerts
    with open("brute_force_alerts.csv", "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "source_ip", "attempt_count", "first_seen", "last_seen", "severity"
        ])
        writer.writeheader()
        writer.writerows(brute_force)
    print("  [+] brute_force_alerts.csv")

    # User enumeration
    with open("user_enumeration.csv", "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["username", "attempt_count"])
        writer.writeheader()
        writer.writerows(enumeration)
    print("  [+] user_enumeration.csv")


# ─── Entry Point ──────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Linux Log File Analyzer — Detects suspicious auth activity"
    )
    parser.add_argument("--log",       default="Linux_2k.log", help="Path to log file")
    parser.add_argument("--threshold", default=5, type=int,    help="Brute force attempt threshold")
    parser.add_argument("--no-export", action="store_true",    help="Skip CSV export")
    args = parser.parse_args()

    print(f"\n[*] Parsing log file: {args.log}")
    entries = parse_log_file(args.log)
    print(f"[*] Parsed {len(entries)} suspicious events")

    brute_force  = detect_brute_force(entries, threshold=args.threshold)
    enumeration  = detect_user_enumeration(entries)

    print_summary(entries, brute_force, enumeration)

    if not args.no_export:
        print("\n[*] Exporting CSV reports...")
        export_csv(entries, brute_force, enumeration)

    print("\n[✓] Analysis complete.\n")


if __name__ == "__main__":
    main()