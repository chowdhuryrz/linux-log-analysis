# Linux SSH Threat Analysis

A end-to-end security project that automates Linux log parsing, detects brute force attacks, and visualizes threat data in a Splunk SIEM dashboard.

![Linux SSH Threat Analysis Dashboard](screenshots/Linux_SSH_Threat_Analysis.png)

---

## Overview

This project simulates a real SOC analyst workflow across three phases: manual log review, automated Python-based detection, and SIEM visualization in Splunk. The goal is to identify brute force attacks and suspicious authentication activity from a real-world Linux syslog dataset.

**Dataset:** `Linux_2k.log` - 2,000 lines of real Linux authentication logs (June-July 2005) from [LogHub](https://github.com/logpai/loghub)

**Tools:** Python 3, Splunk Enterprise, CSV, VS Code

---

## Tools and Technologies

| Tool | Purpose |
|---|---|
| Python 3 | Log parsing, pattern detection, threat scoring, CSV export |
| Splunk Enterprise | SIEM ingestion, SPL queries, dashboard visualization |
| Regex (`re`) | Structured field extraction from raw syslog |
| CSV | Structured output for SIEM ingestion |
| VS Code | Script development and log review |

---

## Project Structure

```
linux-log-analysis/
├── Linux_2k.log               # Raw syslog dataset
├── log_analysis.py            # Python threat detection script
├── suspicious_logs.csv        # All parsed suspicious events
├── brute_force_alerts.csv     # IPs flagged for brute force
├── user_enumeration.csv       # Targeted usernames
└── screenshots/
    └── Linux_SSH_Threat_Analysis.png
```

---

## How It Works

### Phase 1 - Manual Log Review

Before automating anything, the log file was opened in VS Code and reviewed manually. The goal was to identify patterns by eye before writing any code.

Suspicious indicators looked for:

- Repeated failed logins from the same IP address
- "user unknown" messages indicating username guessing
- System alerts such as `logrotate: ALERT exited abnormally`

Early findings from the first 40 lines showed repeated authentication failures from `218.188.2.4` and `220-135-151-1.hinet-ip.hinet.net`, both targeting the `root` account. This established the baseline for what to automate.

### Phase 2 - Automated Detection

The Python script reads the full log file and uses regex patterns to extract structured fields from each line:

- Timestamp, hostname, service, PID
- Source IP, username, event type, severity

Eight event types are detected:

| Event Type | Severity |
|---|---|
| Auth Failure | HIGH |
| Failed Login | HIGH |
| Unknown User | MEDIUM |
| Invalid User | MEDIUM |
| FTP Connection | MEDIUM |
| Session Opened/Closed | INFO |
| Logrotate Alert | LOW |

**Brute Force Detection** flags any IP that exceeds a configurable failure threshold (default: 5 attempts). IPs with 20 or more failures are escalated to CRITICAL severity.

**User Enumeration Detection** identifies usernames that were repeatedly targeted in unknown or invalid user attempts, which is a sign of account enumeration activity.

Three structured CSVs are exported for SIEM ingestion:

- `suspicious_logs.csv` - all parsed events with full field extraction
- `brute_force_alerts.csv` - flagged IPs with attempt counts and timestamps
- `user_enumeration.csv` - targeted usernames and attempt counts

### Phase 3 - Splunk SIEM Dashboard

The CSVs are ingested into Splunk via **Settings > Add Data > Upload**. The following SPL query was used to filter for suspicious authentication activity:

```spl
source="suspicious_logs.csv" ("Failed password" OR "authentication failure" OR "invalid user" OR "user unknown")
```

Results were analyzed across four Splunk views:

- **Events** - scrolled through individual flagged log lines to spot repeat offenders
- **Patterns** - confirmed that "Failed password for root" was the dominant pattern, indicating systematic rather than random activity
- **Statistics** - grouped events by IP and username to identify the highest-volume attackers
- **Visualization** - plotted authentication failures over time as a line chart, revealing sharp bursty spikes consistent with automated brute force scripts

The final dashboard has six panels:

- Severity Distribution (Pie Chart)
- Top 10 Attacking IPs (Bar Chart)
- Attack Timeline by Event Type (Line Chart)
- High and Critical Alert Triage (Table)
- Brute Force Leaderboard (Table)
- Event Breakdown by Type (Bar Chart)

---

## Key Findings

| Finding | Detail |
|---|---|
| Total suspicious events parsed | 852 |
| IPs flagged for brute force | 40 |
| CRITICAL severity IPs | 4 |
| Top attacker | `150.183.249.110` - 80 attempts in under 2 minutes |
| Auth failures | 489 HIGH severity events |
| Unknown user attempts | 117 MEDIUM severity events |

**Top brute force attackers:**

| IP | Attempts | Severity | Window |
|---|---|---|---|
| 150.183.249.110 | 80 | CRITICAL | Jul 10 16:01 - 16:03 |
| 207.243.167.114 | 23 | CRITICAL | Jul 26 07:02 - 07:04 |
| n219076184117.netvigator.com | 23 | CRITICAL | Jun 22 03:17 - 03:18 |
| 60.30.224.116 | 20 | CRITICAL | Jun 30 - Jul 1 |

The activity pattern across all top attackers is consistent with automated brute force scripts targeting the `root` account, with bursts of attempts occurring within seconds of each other.

---

## Usage

```bash
# Basic usage
python log_analysis.py

# Custom log file and threshold
python log_analysis.py --log /path/to/file.log --threshold 10

# Skip CSV export
python log_analysis.py --no-export
```

**Requirements:** Python 3.7+ (no external dependencies)

---

## Splunk SPL Queries

```spl
# Top attacking IPs
source="suspicious_logs.csv" | stats count by source_ip | sort -count | head 10

# Severity distribution
source="suspicious_logs.csv" | stats count by severity | sort -count

# Attack timeline
source="suspicious_logs.csv" | timechart count by event_type

# Brute force leaderboard
source="brute_force_alerts.csv" | table source_ip attempt_count severity first_seen last_seen | sort -attempt_count

# High/Critical triage
source="suspicious_logs.csv" severity="HIGH" OR severity="CRITICAL" | table timestamp source_ip username event_type severity | sort timestamp
```

---

## Author

**Rohan Chowdhury**

[GitHub](https://github.com/chowdhuryrz) | [LinkedIn](https://linkedin.com/in/rohan-chowdhury)
