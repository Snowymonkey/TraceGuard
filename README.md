# TraceGuard

TraceGuard is a command-line cybersecurity log analysis tool designed to detect, correlate, and report suspicious activity across Apache web server logs and Linux authentication logs. It is built for local forensic analysis, incident response triage, and security research, focusing on identifying behavioral indicators of compromise such as brute-force attacks, privilege escalation abuse, and multi-stage attack chains.

The tool analyzes log data from multiple sources, extracts structured events, detects anomalies using frequency and temporal patterns, and generates human-readable security reports for investigation.

---

## Features

TraceGuard provides a lightweight but effective detection pipeline for local security analysis:

- Multi-source log ingestion (Apache HTTP logs, Linux auth logs)
- Detection of HTTP anomalies (e.g., 404 spikes, abnormal request patterns)
- SSH authentication attack detection (brute-force and failure patterns)
- Sudo privilege escalation monitoring and abuse detection
- Cross-log correlation of related events into multi-stage attack chains
- Structured forensic reporting for IPs, users, and attack sequences
- Configurable verbosity and evidence-level logging
- Fully offline, dependency-free execution (Python standard library only)

---

## TraceGuard Architecture

```text
                    ┌─────────────┐
                    │  Log Files  │
                    └──────┬──────┘
                           │
                           ▼
                    ┌─────────────┐
                    │  router.py  │
                    └──────┬──────┘
                           │
         ┌─────────────────┴─────────────────┐
         │                                   │
         ▼                                   ▼
 ┌─────────────────┐               ┌─────────────────┐
 │ Apache Parser   │               │ Linux Parsers   │
 │                 │               │                 │
 │ • HTTP Requests │               │ • SSH Events    │
 │ • Status Codes  │               │ • Sudo Events   │
 │ • Source IPs    │               │ • User Activity │
 └────────┬────────┘               └────────┬────────┘
          │                                 │
          └──────────────┬──────────────────┘
                         │
                         ▼
               ┌─────────────────┐
               │ Parsed Log Data │
               └────────┬────────┘
                        │
                        ▼
               ┌─────────────────┐
               │ Analysis Engine │
               └────────┬────────┘
                        │
        ┌───────────────┼────────────────┐
        │               │                │
        ▼               ▼                ▼
 ┌─────────────┐ ┌─────────────┐ ┌─────────────┐
 │ HTTP Attack │ │ SSH Attack  │ │ Sudo Abuse  │
 │ Detection   │ │ Detection   │ │ Detection   │
 └──────┬──────┘ └──────┬──────┘ └──────┬──────┘
        │               │               │
        └───────────────┼───────────────┘
                        │
                        ▼
              ┌──────────────────┐
              │ Alert Generation │
              └────────┬─────────┘
                       │
                       ▼
            ┌──────────────────────┐
            │ Correlation Engine   │
            │ (Attack Chaining)    │
            └──────────┬───────────┘
                       │
                       ▼
             ┌────────────────────┐
             │ report_writer.py   │
             └──────────┬─────────┘
                        │
                        ▼
      ┌──────────────────────────────────┐
      │ Generated Reports                │
      │                                  │
      │ • ip_logs                        │
      │ • sudo_logs                      │
      │ • ip_reports                     │
      │ • sudo_reports                   │
      │ • multi-chain-reports            │
      └──────────────────────────────────┘
```

---

## Installation

### Requirements

- Python 3.9 or higher

### Clone the Repository

```bash
git clone https://github.com/Snowymonkey/TraceGuard
cd traceguard
```

No additional installation is required.

---

## Usage

Before you start using `TraceGuard` it would be smart to run the unit tests.

```bash
python tester.py
```

| Argument | Description |
|-----------|------------|
| `-f`, `--file` | Analyze a single log file |
| `-d`, `--directory` | Analyze all supported log files in a directory |
| `-e`, `--export` | Output directory for generated reports |
| `-v`, `--verbose` | Enable runtime status logging |
| `--version` | Display version information |

### Analyze a Single Log File

```bash
python traceguard.py --file /path/to/logfile
python traceguard.py -f /path/to/logfile
```

### Analyze a Directory of Logs

```bash
python traceguard.py --directory /path/to/logs
python traceguard.py -d /path/to/logs
```

### Enable Verbose Output

```bash
python traceguard.py --verbose -f logs/apache-log
python traceguard.py -v -f logs/apache.log 
```

### Specify a Custom Export Directory

```bash
python traceguard.py -f logs/apache.log --export output/
```

### Display Version Information

```bash
python traceguard.py --version
```

---

## Output Reports

TraceGuard generates multiple forensic artifacts in the specified export directory.

### `ip_logs`

Aggregated IP-based activity counts.

### `sudo_logs`

Aggregated sudo activity by user.

### `ip_reports`

Detailed security alerts related to:

- HTTP anomalies
- SSH brute-force attempts
- Authentication abuse
- Attack classifications

### `sudo_reports`

Privilege escalation and sudo abuse reports.

### `multi-chain-reports`

Correlated attack chains representing:

```text
Reconnaissance → Access Attempt → Breach
```

---

## Configuration

Configuration is controlled through:

```text
analysis/config.json
```

Example:
```json
{
    "ssh_failed_threshold" : 0,

    "http_400_threshold" : 0,
    "unique_404_threshold" : 0,
    "404_error_timeframe" : 10,

    "sudo_commands_timeframe" : 10,
    "sudo_threshold" : 0,

    "show_full_logs_on_alert" : true
}
```

### Available Options

| Setting | Description |
|----------|------------|
| `ssh_failed_threshold` | Threshold for failed SSH password attempts until triggered alert |
| `sudo_threshold` | Threshold for number of sudo commands until triggered alert |
| `http_400_threshold` | Threshold for (400 - 499) client error responses until triggered alert |
| `unique_404_threshold` | Threshold for 404 error responses until triggered alert |
| `404_error_timeframe` | Time window (in seconds) used to group and evaluate HTTP 404 errors for anomaly detection. |
| `sudo_commands_timeframe` | Time window (in seconds) used to group and evaluate sudo commands for anomaly detection. |
| `show_full_logs_on_alert` | Include raw log evidence in generated alerts |

## Notes

- Designed for offline log analysis
- Overwrites report files on each execution
- Assumes structured or semi-structured log inputs

---

## Version

**TraceGuard 1.0.0**
