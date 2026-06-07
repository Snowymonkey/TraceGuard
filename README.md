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
               │Detection Engine │
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
git clone <repo-url>
cd traceguard
```

No additional installation is required.

---

## Usage

### Analyze a Single Log File

```bash
python cli.py --file /path/to/logfile
```

### Analyze a Directory of Logs

```bash
python cli.py --directory /path/to/logs
```

### Enable Verbose Output

```bash
python cli.py --file logs/apache.log --verbose
```

### Specify a Custom Export Directory

```bash
python cli.py --file logs/apache.log --export output/
```

### Display Version Information

```bash
python cli.py --version
```

---
