# Linux Hardening Audit Tool

## Project Overview

The Linux Hardening Audit Tool is a Python-based cybersecurity project designed to perform basic security configuration checks on a Linux system.

It helps identify selected security configuration issues and generates an audit report with a basic security score and recommendations.

## Author

**Aritra  Pal**
Cybersecurity Student |

Cyber Crime Investigator and Fraud Analyst

## Features

- Linux system information collection
- UFW firewall status check
- SSH root-login configuration review
- Sensitive file permission audit
- Basic security scoring system
- Security recommendations
- TXT and JSON report generation

## Technologies Used

- Python 3
- Kali Linux
- Linux command-line tools
- JSON

## Project Structure

```text
Linux-Hardening-Audit-Tool/
├── audit.py
├── README.md
├── requirements.txt
├── reports/
│   ├── audit_report.txt
│   └── audit_report.json
└── screenshots/
```

## Installation and Usage

Clone the repository:

```bash
git clone https://github.com/YOUR-USERNAME/Linux-Hardening-Audit-Tool.git
```

Enter the project directory:

```bash
cd Linux-Hardening-Audit-Tool
```

Run the audit:

```bash
python3 audit.py
```

View the text report:

```bash
cat reports/audit_report.txt
```

View the JSON report:

```bash
cat reports/audit_report.json
```

## Output

The tool generates:

- `audit_report.txt`
- `audit_report.json`

## Disclaimer

This project is developed for educational and defensive cybersecurity purposes. The security score is a basic estimate and does not represent a complete security assessment or official compliance certification.
