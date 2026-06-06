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

## Project Structure

```text
traceguard/
├── cli.py                  # CLI entry point
├── router.py              # Log routing + analysis dispatcher
├── analysis/
│   └── config.json        # Configuration file
├── reports/               # Default output directory (auto-generated)
└── logs/                  # Optional input logs
```

