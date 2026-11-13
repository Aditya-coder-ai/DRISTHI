# Web Admin Portal Deception Service (Phase 3)

## Overview
The Web Admin Portal Deception Service simulates an enterprise internal administration system (**Apex Internal Management System** for **Apex Financial Group**, representing `web-admin.corp.internal` / `10.0.1.20:8080`).

It is engineered with FastAPI, Jinja2, and custom HTML5/CSS3 to provide an authentic, deceptive attack surface that lures adversaries into interacting with believable corporate dashboards, employee records, financial ledgers, simulated database consoles, and configuration profiles containing bait credentials.

## Key Features
- **Corporate UI Authenticity**: High-fidelity dark corporate theme matching proprietary financial internal portals, with responsive layouts, metric summaries, and real-time SIEM activity logs.
- **Strict Security & Zero Real Infrastructure Exposure**:
  - Passwords are never stored or logged in plaintext — redacted to `password_length` in all telemetry.
  - Database console evaluates queries against in-memory datasets (`EMPLOYEES`, `CUSTOMERS`, `INVOICES`) with no real database connection or arbitrary execution.
  - Decoy financial documents (`Q4_consolidated_financials.pdf`, `payroll_tax_filing_2026.xlsx`, `annual_audit_summary.csv`) are served with correct MIME headers while logging exfiltration attempts.
- **Interaction Monitoring & Attack Detection**:
  - **Brute Force Detection**: Flags IP addresses and accounts with $\ge 3$ failed attempts as `brute_force_detected: true` with `alert_priority: HIGH`.
  - **Bait Credential Triggers**: Detects logins using `finance_admin`, `backup_user`, `database_root`, or `admin`, flagging `bait_credential_triggered: true` with `alert_priority: HIGH`.
  - **Reconnaissance & Vulnerability Scanner Detection**: Automatically catches probes for common endpoints (`/.env`, `/wp-admin`, `/phpmyadmin`, `/.git`, path traversal `..`) and emits `SUSPICIOUS_REQUEST` events.
  - **Configuration File Bait**: Decoy configuration profiles (`database_config.json`, `backup_config.json`, `application.env.example`) plant credentials (`database_root:DBroot@2026`) and trigger `BAIT_CREDENTIAL_TRIGGER` upon access.
- **Central Backend Forwarding with Offline Resilience**:
  - `collector/forwarder.py`: Sends normalized batches to Central Backend with configurable timeouts and authentication.
  - `collector/retry_queue.py`: Thread-safe SQLite queue with deduplication, retry tracking, exponential backoff, and dead-letter queueing when backend is unreachable.

## Architecture & Directory Layout
```text
services/web/
├── app.py                      # FastAPI application with reconnaissance middleware
├── runner.py                   # Service lifecycle CLI (run, start, stop, status)
├── security.py                 # Session management, rate-limiting & telemetry dispatch
├── web_event_adapter.py        # Maps HTTP telemetry to unified SecurityEvent schema
├── data/
│   └── seed_data.py            # Fictional employees, customers, invoices, and decoy files
├── routes/
│   ├── auth.py                 # Login, brute-force tracking, session cookie management
│   ├── dashboard.py            # Operations dashboard & infrastructure topology
│   ├── employees.py            # Employee directory and individual employee API
│   ├── finance.py              # Financial operations & decoy document downloads
│   ├── database.py             # Relational cluster view & safe SQL query console
│   └── configuration.py        # System configuration profiles & bait file viewer
├── static/
│   └── css/
│       └── portal.css          # Professional corporate CSS styling
├── templates/
│   ├── base.html               # Corporate layout, sidebar, header, navigation
│   ├── login.html              # Admin login interface
│   ├── dashboard.html          # Executive operations dashboard
│   ├── employees.html          # Corporate personnel roster
│   ├── finance.html            # Financial operations & decoy report downloads
│   ├── database.html           # Database cluster view & simulated query console
│   └── configuration.html      # Host details & bait configuration file viewer
└── README.md
```

## Running the Service

### Foreground Mode
```powershell
.venv\Scripts\python.exe services/web/runner.py run --port 8080 --host 0.0.0.0
```

### Background Daemon Mode
```powershell
# Start daemon
.venv\Scripts\python.exe services/web/runner.py start

# Check status
.venv\Scripts\python.exe services/web/runner.py status

# Stop daemon
.venv\Scripts\python.exe services/web/runner.py stop
```

## Simulating an Attack
Run the automated adversary interaction script:
```powershell
.venv\Scripts\python.exe scripts/simulate_web_attack.py
```
This simulates:
1. Scanner reconnaissance probes (`/.env`, `/wp-admin`, path traversal).
2. Brute-force password guessing.
3. Login using bait credentials (`finance_admin / Finance@2026`).
4. Viewing personnel directory and ledgers.
5. Exfiltrating confidential decoy financial PDF and Excel reports.
6. Executing queries in the SQL console.
7. Accessing decoy configuration profiles containing database credentials.
8. Verifying captured security telemetry.

## Running Tests
```powershell
.venv\Scripts\python.exe -m pytest tests/test_web_adapter.py tests/test_web_portal.py tests/test_backend_forwarder.py -v
```
