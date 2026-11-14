# Deception-Based Cybersecurity Platform — Person 1 Module
## Deception Assets & Honeypot Infrastructure (Phases 1–7 Complete)

### Author & Role
- **Role**: Senior Cybersecurity Engineer, Python Backend Developer, Honeypot Infrastructure Specialist (Person 1)
- **Objective**: Realistic, controlled deception environment containing fake services, decoy systems, bait credentials, canary detection, and normalized event forwarding.
- **Current Status**: **ALL 7 PHASES COMPLETE & FULLY OPERATIONAL (61 / 61 TESTS PASSING)**

---

## Architecture Overview

```text
deception-assets/
├── services/
│   ├── ssh/                     # Phase 1: SSH Deception (Cowrie on port 2222)
│   │   ├── config/              # Server configuration and userdb
│   │   ├── honeyfs/             # Linux filesystem overlays & breadcrumbs
│   │   ├── runner.py            # Service lifecycle management
│   │   ├── ssh_event_adapter.py # Cowrie -> SecurityEvent adapter
│   │   └── README.md
│   ├── ftp/                     # Phase 2: FTP Deception (Isolated VFS on port 2121)
│   │   ├── config/              # Server configuration and credentials
│   │   ├── decoy_root/          # Virtual decoy directory tree
│   │   ├── vfs.py               # Virtual Filesystem with traversal protection
│   │   ├── server.py            # Async RFC 959 FTP Honeypot server
│   │   ├── runner.py            # Service lifecycle management
│   │   ├── ftp_event_adapter.py # FTP -> SecurityEvent adapter
│   │   └── README.md
│   ├── web/                     # Phase 3: Web Admin Portal (FastAPI on port 8080)
│   │   ├── app.py               # FastAPI application with reconnaissance middleware
│   │   ├── runner.py            # Service lifecycle management (Uvicorn)
│   │   ├── security.py          # Session tracking & telemetry logger
│   │   ├── web_event_adapter.py # HTTP telemetry -> SecurityEvent adapter
│   │   ├── data/                # Fictional corporate seed data & decoy reports
│   │   ├── routes/              # Modular routes (auth, dashboard, employees, finance, db, config)
│   │   ├── static/              # Corporate CSS styling
│   │   ├── templates/           # Jinja2 corporate HTML templates
│   │   └── README.md
│   ├── database/                # Phase 4: Fake Database Service (PG 5432 & MySQL 3306)
│   │   ├── data/                # In-memory relational tables & schema definitions
│   │   ├── postgres_server.py   # Async PostgreSQL v3.0 wire protocol honeypot
│   │   ├── mysql_server.py      # Async MySQL client/server protocol honeypot
│   │   ├── db_event_adapter.py  # Database telemetry -> SecurityEvent adapter (db-001)
│   │   ├── runner.py            # Service lifecycle management
│   │   └── README.md
│   └── credentials/             # Phase 5: Dynamic Bait Credentials & Canaries
│       ├── registry.py          # Central registry, rotation & cross-service reuse detection
│       └── README.md
├── credentials/                 # Bait Credential Files
│   └── decoy_credentials.json
├── collector/                   # Phase 6: Central Event Collection & Forwarding
│   ├── normalizer.py            # Unified Protocol -> SecurityEvent dispatcher
│   ├── event_collector.py       # Thread-safe in-memory & file buffer
│   ├── retry_queue.py           # SQLite persistent retry queue with exponential backoff
│   ├── forwarder.py             # HTTP batch forwarder with retry fallback
│   └── daemon.py                # Collector daemon with health check & operational CLI
├── shared/                      # Shared Models & Utilities
│   ├── event_schema.py          # Unified SecurityEvent schema
│   ├── config.py                # Central environment configuration
│   └── logger.py                # Structured logging
├── tests/                       # Automated Verification Suite (61 Passing Tests)
│   ├── test_event_schema.py     # Schema validation & serialization
│   ├── test_ssh_adapter.py      # SSH telemetry normalization
│   ├── test_ssh_deception.py    # Live SSH honeypot operations
│   ├── test_ftp_vfs.py          # VFS isolation & traversal security
│   ├── test_ftp_adapter.py      # FTP telemetry normalization
│   ├── test_ftp_deception.py    # Live FTP server operations
│   ├── test_web_adapter.py      # Web telemetry normalization & redaction
│   ├── test_web_portal.py       # Web portal integration & authentication
│   ├── test_database_deception.py# PostgreSQL & MySQL protocols and query isolation
│   ├── test_credentials_registry.py# Canary triggers & lateral movement detection
│   ├── test_backend_forwarder.py# SQLite retry queue & event forwarder
│   ├── test_collector_daemon.py # Collector daemon lifecycle & health checks
│   └── test_e2e_integration.py  # Full end-to-end multi-service integration
├── scripts/                     # Adversary Simulation Scripts
│   ├── simulate_ssh_attack.py   # SSH brute force & command execution
│   ├── simulate_ftp_attack.py   # FTP reconnaissance & exfiltration
│   ├── simulate_web_attack.py   # Web recon, brute force & bait trigger
│   └── simulate_full_killchain.py# Multi-stage kill-chain across all 4 assets
├── docker-compose.yml           # Phase 7: Multi-container deployment
├── Dockerfile                   # Unified container build
├── requirements.txt
├── .env.example
├── .gitignore
└── README.md
```

---

## Integration Contracts

| Module Owner | Domain | Contract / Interface |
|---|---|---|
| **Person 1 (Us)** | Deception Assets, HoneyFS, Canaries, Event Forwarder | Emits validated `SecurityEvent` JSON objects via HTTP/Collector daemon |
| **Person 2** | Central Backend & Event Persistence | Consumes normalized `SecurityEvent` batches via `POST /api/events` |
| **Person 3** | Threat Detection & Intelligence | Evaluates `SecurityEvent` streams for MITRE mapping & risk scoring |
| **Person 4** | Dashboard & Visualization | Displays decoy activity, attack timelines, and canary alerts |

---

## Summary of All Implemented Phases (1–7)

### Phase 1: SSH Deception (`ssh-001`, Port 2222)
- Simulates Linux server (`finance-server`).
- HoneyFS provides believable directory structures (`/etc/passwd`, `/etc/shadow`, `/home/finance_admin/.bash_history`).
- Configured with decoy bait credential `finance_admin:Finance@2026`.
- Virtual shell isolation with structured JSON logging and `CowrieSSHAdapter`.

### Phase 2: FTP Deception (`ftp-001`, Port 2121)
- RFC 959 asynchronous FTP honeypot (`Corp-Storage-Node-02`).
- Jailed Virtual Filesystem (VFS) with directory traversal clamping (`..` strictly prevented).
- Decoy files: `customer_database.sql`, `backup.zip`, `db_migration_notes.txt`, `employee_records.csv`, `financial_report.xlsx`.
- Bait account: `backup_user:Backup@2026`.

### Phase 3: Web Admin Portal (`web-001`, Port 8080)
- **Apex Financial Group** (*Apex Internal Management System*).
- 6 views: Admin Login, Operations Dashboard, Employee Directory, Financial Ledgers, Database Management, System Configuration.
- Interaction monitoring: Brute force detection ($\ge 3$ attempts), password redaction (`password_length`), scanner reconnaissance probes (`/.env`, `/wp-admin`), and decoy report downloads.

### Phase 4: Database Deception (`db-001`, Ports 5432 & 3306)
- **PostgreSQL v3.0 Protocol Engine (5432)** & **MySQL Protocol Engine (3306)**.
- Safe in-memory schemas: `corporate_finance`, `employee_records`, `customer_accounts`, `payroll_2026`, `transaction_history`.
- Responds to `SHOW TABLES`, `SHOW DATABASES`, and SQL queries with believable records while maintaining 100% isolation from host storage.
- Bait account: `database_root:DBroot@2026`.

### Phase 5: Dynamic Bait Credentials Registry & Canaries
- Centralized registry (`services/credentials/registry.py`) with SHA-256 verification and rotation support.
- Canary Detection: Emits `CANARY_TRIGGERED` whenever a registered decoy credential is used.
- Cross-Service Correlation: Detects when credentials planted on one honeypot (e.g. `ssh-001` or `ftp-001`) are reused on another (e.g. `db-001`), generating high-priority `CREDENTIAL_REUSE` lateral movement alerts.

### Phase 6: Central Event Collection & Forwarding Daemon
- Reliable collector daemon (`collector/daemon.py`) with CLI controls (`start`, `stop`, `restart`, `status`, `health`, `flush`).
- SQLite persistent retry queue (`var/data/retry_queue.db`) ensuring at-least-once delivery with exponential backoff, dead-letter state transitions, and deduplication.
- Live health check reporting: uptime, delivery counts, queue depth, dead-letter stats.

### Phase 7: End-to-End Testing & Containerized Multi-Service Deployment
- `docker-compose.yml` orchestrates all 4 honeypot services and the collector daemon in isolated containers.
- Multi-stage `scripts/simulate_full_killchain.py` simulates realistic adversary progression across SSH $\to$ FTP $\to$ Web $\to$ Database $\to$ Canary Correlation $\to$ Daemon Forwarding.
- Complete automated pytest suite of 61 tests passing with 100% success rate.

---

## Verification & Automated Test Suite

Run all 61 tests across all phases:
```powershell
.venv\Scripts\python.exe -m pytest tests/ -v
```

```text
============================= test session starts =============================
platform win32 -- Python 3.12.13, pytest-9.2.0, pluggy-1.7.0
rootdir: C:\Users\adij7\OneDrive\Attachments\Desktop\DRISHTI

tests/test_backend_forwarder.py::test_retry_queue_enqueue_and_deduplication PASSED
tests/test_backend_forwarder.py::test_retry_queue_dequeue_batch_and_mark_success PASSED
tests/test_backend_forwarder.py::test_retry_queue_exponential_backoff_and_dead_letter PASSED
tests/test_backend_forwarder.py::test_forwarder_send_event_success PASSED
tests/test_backend_forwarder.py::test_forwarder_send_event_failure_buffers_to_retry_queue PASSED
tests/test_backend_forwarder.py::test_forwarder_flush_retry_queue PASSED
tests/test_collector_daemon.py::test_daemon_health_stats_initial PASSED
tests/test_collector_daemon.py::test_daemon_drain_collector_and_flush_success PASSED
tests/test_collector_daemon.py::test_daemon_flush_failure_and_degraded_status PASSED
tests/test_credentials_registry.py::test_registry_seed_credentials_loaded PASSED
tests/test_credentials_registry.py::test_registry_registration PASSED
tests/test_credentials_registry.py::test_canary_trigger_on_origin_asset PASSED
tests/test_credentials_registry.py::test_cross_service_lateral_movement_reuse_detection PASSED
tests/test_credentials_registry.py::test_credential_rotation PASSED
tests/test_database_deception.py::test_seed_db_query_isolation_and_results PASSED
tests/test_database_deception.py::test_db_adapter_failed_login PASSED
tests/test_database_deception.py::test_db_adapter_bait_login_success PASSED
tests/test_database_deception.py::test_db_adapter_query_enumeration PASSED
tests/test_database_deception.py::test_normalizer_facade_dispatches_database PASSED
tests/test_database_deception.py::test_live_postgres_protocol_flow PASSED
tests/test_database_deception.py::test_live_mysql_protocol_flow PASSED
tests/test_e2e_integration.py::test_full_cross_service_lifecycle_e2e PASSED
tests/test_event_schema.py::test_security_event_creation_valid PASSED
tests/test_event_schema.py::test_security_event_invalid_timestamp PASSED
tests/test_event_schema.py::test_security_event_json_serialization PASSED
tests/test_ftp_adapter.py::test_normalize_failed_ftp_login PASSED
tests/test_ftp_adapter.py::test_normalize_bait_credential_login PASSED
tests/test_ftp_adapter.py::test_normalize_ftp_directory_list PASSED
tests/test_ftp_adapter.py::test_normalize_ftp_file_download PASSED
tests/test_ftp_adapter.py::test_normalize_ftp_suspicious_request PASSED
tests/test_ftp_deception.py::test_ftp_failed_login PASSED
tests/test_ftp_deception.py::test_ftp_successful_bait_login_and_operations PASSED
tests/test_ftp_vfs.py::test_vfs_path_resolution_security PASSED
tests/test_ftp_vfs.py::test_vfs_host_filesystem_isolation PASSED
tests/test_ftp_vfs.py::test_vfs_decoy_tree_contents PASSED
tests/test_ftp_vfs.py::test_vfs_file_read_and_store PASSED
tests/test_ssh_adapter.py::test_normalize_failed_login PASSED
tests/test_ssh_adapter.py::test_normalize_bait_credential_login PASSED
tests/test_ssh_adapter.py::test_normalize_command_execution PASSED
tests/test_ssh_adapter.py::test_normalize_file_upload PASSED
tests/test_ssh_deception.py::test_ssh_honeyfs_assets_exist PASSED
tests/test_ssh_deception.py::test_ssh_failed_login_and_event_generation PASSED
tests/test_ssh_deception.py::test_ssh_successful_login_and_command_execution PASSED
tests/test_web_adapter.py::test_normalize_failed_login_redaction PASSED
tests/test_web_adapter.py::test_normalize_brute_force_detection PASSED
tests/test_web_adapter.py::test_normalize_bait_credential_login PASSED
tests/test_web_adapter.py::test_normalize_decoy_report_download PASSED
tests/test_web_adapter.py::test_normalize_bait_configuration_trigger PASSED
tests/test_web_adapter.py::test_normalize_suspicious_scanner_probe PASSED
tests/test_web_adapter.py::test_normalizer_facade_dispatches_http PASSED
tests/test_web_portal.py::test_login_page_renders PASSED
tests/test_web_portal.py::test_unauthenticated_redirect PASSED
tests/test_web_portal.py::test_failed_login_redacts_password_and_logs_event PASSED
tests/test_web_portal.py::test_brute_force_detection PASSED
tests/test_web_portal.py::test_successful_bait_login_sets_cookie PASSED
tests/test_web_portal.py::test_authenticated_dashboard_and_employees PASSED
tests/test_web_portal.py::test_decoy_report_download PASSED
tests/test_web_portal.py::test_safe_database_query_console PASSED
tests/test_web_portal.py::test_view_bait_configuration_file PASSED
tests/test_web_portal.py::test_suspicious_scanner_probes_blocked_and_logged PASSED
tests/test_web_portal.py::test_logout_terminates_session PASSED
============================== 61 passed in 13.51s ==============================
```

---

## Operational Runbooks

### 1. Running Individual Services (Foreground or Daemon)

```powershell
# SSH Honeypot (Port 2222)
.venv\Scripts\python.exe services/ssh/runner.py run --port 2222

# FTP Honeypot (Port 2121)
.venv\Scripts\python.exe services/ftp/runner.py run --port 2121

# Web Admin Portal (Port 8080)
.venv\Scripts\python.exe services/web/runner.py run --port 8080

# Database Honeypots (PostgreSQL 5432 & MySQL 3306)
.venv\Scripts\python.exe services/database/runner.py run --pg-port 5432 --mysql-port 3306

# Collector Forwarding Daemon
.venv\Scripts\python.exe collector/daemon.py start
.venv\Scripts\python.exe collector/daemon.py health
```

### 2. Multi-Container Deployment via Docker Compose

```bash
# Build and start all deception services
docker-compose up -d --build

# View real-time aggregated logs
docker-compose logs -f

# Check container status
docker-compose ps

# Stop all services
docker-compose down
```

### 3. Executing Full Kill-Chain Simulation

```powershell
.venv\Scripts\python.exe scripts/simulate_full_killchain.py
```
