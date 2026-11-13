# Deception-Based Cybersecurity Platform — Person 1 Module
## Deception Assets & Honeypot Infrastructure

### Author & Role
- **Role**: Senior Cybersecurity Engineer, Python Backend Developer, Honeypot Infrastructure Specialist (Person 1)
- **Objective**: Realistic, controlled deception environment containing fake services, decoy systems, bait credentials, and normalized event collection.

---

## Architecture Overview

```text
deception-assets/
├── services/
│   ├── ssh/                     # Phase 1: SSH Deception (Cowrie)
│   │   ├── config/              # Server configuration and userdb
│   │   ├── honeyfs/             # Linux filesystem overlays & breadcrumbs
│   │   ├── runner.py            # Service lifecycle management
│   │   ├── ssh_event_adapter.py # Cowrie -> SecurityEvent adapter
│   │   └── README.md
│   ├── ftp/                     # Phase 2: FTP Deception (Isolated VFS)
│   │   ├── config/              # Server configuration and credentials
│   │   ├── decoy_root/          # Virtual decoy directory tree
│   │   ├── vfs.py               # Virtual Filesystem with traversal protection
│   │   ├── server.py            # Async RFC 959 FTP Honeypot server
│   │   ├── runner.py            # Service lifecycle management
│   │   ├── ftp_event_adapter.py # FTP -> SecurityEvent adapter
│   │   └── README.md
│   ├── web/                     # Phase 3: Web Admin Portal Deception (FastAPI)
│   │   ├── app.py               # FastAPI application with reconnaissance middleware
│   │   ├── runner.py            # Service lifecycle management (Uvicorn)
│   │   ├── security.py          # Session tracking & telemetry logger
│   │   ├── web_event_adapter.py # HTTP telemetry -> SecurityEvent adapter
│   │   ├── data/                # Fictional corporate seed data & bait configs
│   │   ├── routes/              # Modular routes (auth, dashboard, employees, finance, db, config)
│   │   ├── static/              # Corporate CSS styling
│   │   ├── templates/           # Jinja2 corporate HTML templates
│   │   └── README.md
│   └── database/                # Phase 4: Fake Database (Pending)
├── credentials/                 # Phase 5: Bait Credentials Management
│   └── decoy_credentials.json
├── collector/                   # Event Collection, Normalization & Forwarding
│   ├── normalizer.py            # Unified Protocol -> SecurityEvent dispatcher
│   ├── event_collector.py       # Thread-safe in-memory & file buffer
│   ├── retry_queue.py           # SQLite persistent retry queue with exponential backoff
│   └── forwarder.py             # HTTP batch forwarder with retry fallback
├── shared/                      # Shared Models & Utilities
│   ├── event_schema.py          # Unified SecurityEvent schema
│   ├── config.py                # Central environment configuration
│   └── logger.py                # Structured logging
├── tests/                       # Automated Verification Suite (45 Passing Tests)
│   ├── test_event_schema.py     # Schema validation & serialization
│   ├── test_ssh_adapter.py      # SSH telemetry normalization
│   ├── test_ssh_deception.py    # Live SSH honeypot operations
│   ├── test_ftp_vfs.py          # VFS isolation & traversal security
│   ├── test_ftp_adapter.py      # FTP telemetry normalization
│   ├── test_ftp_deception.py    # Live FTP server operations
│   ├── test_web_adapter.py      # Web telemetry normalization & redaction
│   ├── test_web_portal.py       # Web portal integration & authentication
│   └── test_backend_forwarder.py# SQLite retry queue & event forwarder
├── scripts/                     # Adversary Simulation Scripts
│   ├── simulate_ssh_attack.py   # SSH brute force & command execution
│   ├── simulate_ftp_attack.py   # FTP reconnaissance & exfiltration
│   └── simulate_web_attack.py   # Web recon, brute force & bait trigger
├── requirements.txt
├── .env.example
└── README.md
```

---

## Integration Contracts

| Module Owner | Domain | Contract / Interface |
|---|---|---|
| **Person 1 (Us)** | Deception Assets, HoneyFS, Event Normalization | Emits validated `SecurityEvent` JSON objects via HTTP/Collector |
| **Person 2** | Central Backend & Event Persistence | Consumes normalized `SecurityEvent` via `POST /api/events` |
| **Person 3** | Threat Detection & Intelligence | Evaluates `SecurityEvent` streams for MITRE mapping & risk scoring |
| **Person 4** | Dashboard & Visualization | Displays decoy activity and attack timelines |

---

## Implemented Phases

### Phase 1: SSH Deception (Cowrie)
- Emulates a production Linux server (`finance-server`).
- HoneyFS provides believable directory structures (`/etc/hosts`, `/etc/passwd`, `/etc/shadow`, `/home/finance_admin/.bash_history`, `/var/financial_data/Q4_payroll_summary.csv`).
- Configured with decoy bait credential `finance_admin:Finance@2026`.
- Simulates Linux shell safely using Cowrie's virtual filesystem (no host command execution).
- Collects and normalizes authentication failures, successful logins, command executions, and file transfers into unified `SecurityEvent` schema (`asset_id: ssh-001`).

### Phase 2: FTP Deception (Isolated VFS)
- Emulates a corporate offsite backup gateway (`Corp-Storage-Node-02` at port 2121).
- Strictly jailed Virtual Filesystem (VFS) with directory traversal protection; absolute paths, drive letters, and `..` escape vectors cannot access the host filesystem.
- Populated with rich decoy assets (`customer_database.sql`, `backup.zip`, `db_migration_notes.txt`, `employee_records.csv`, `financial_report.xlsx`).
- Configured with bait account `backup_user:Backup@2026` discovered on the SSH server.
- Supports RFC 959 passive mode transfers for listings (`LIST`), downloads (`RETR`), and uploads (`STOR`).
- Captures and normalizes connection, authentication, directory listings, file downloads, uploads, and path traversal attempts into unified `SecurityEvent` schema (`asset_id: ftp-001`).

### Phase 3: Web Admin Portal Deception (FastAPI)
- Emulates the **Apex Internal Management System** for **Apex Financial Group** (`web-admin.corp.internal` at port 8080).
- Authentic corporate UI with 6 distinct views:
  1. **Admin Login Page**: Brute-force tracking, password redaction (`password_length`), and bait credential handling.
  2. **Executive Dashboard**: Corporate statistics, recent SIEM operations, and infrastructure topology.
  3. **Employee Directory**: Corporate personnel roster with individual employee inspection API.
  4. **Financial Operations**: Accounts receivable, enterprise customer ledgers, and downloadable decoy confidential reports (`.pdf`, `.xlsx`, `.csv`).
  5. **Database Management**: Read-only simulated SQL management console executing queries over safe in-memory tables.
  6. **System Configuration**: Gateway architecture and decoy configuration profiles (`database_config.json`, `backup_config.json`, `application.env.example`) planting bait credentials (`database_root:DBroot@2026`).
- **Interaction Monitoring**:
  - Middleware intercepts reconnaissance probes targeting common scanner endpoints (`/.env`, `/wp-admin`, `/phpmyadmin`, path traversal `..`).
  - Brute force detector flags $\ge 3$ failed attempts as `HIGH` priority alert.
  - Bait account logins (`finance_admin`, `backup_user`, `database_root`, `admin`) trigger `HIGH` priority security events.
- **Backend Integration**:
  - `collector/forwarder.py`: Transmits batches of events to Person 2's backend.
  - `collector/retry_queue.py`: Thread-safe SQLite buffer ensuring at-least-once delivery with exponential backoff and deduplication.

---

## Verification & Automated Test Suite

All 45 tests across all phases run in ~13 seconds with 100% pass rate:
```powershell
.venv\Scripts\python.exe -m pytest tests/ -v
```

```text
tests/test_backend_forwarder.py::test_retry_queue_enqueue_and_deduplication PASSED
tests/test_backend_forwarder.py::test_retry_queue_dequeue_batch_and_mark_success PASSED
tests/test_backend_forwarder.py::test_retry_queue_exponential_backoff_and_dead_letter PASSED
tests/test_backend_forwarder.py::test_forwarder_send_event_success PASSED
tests/test_backend_forwarder.py::test_forwarder_send_event_failure_buffers_to_retry_queue PASSED
tests/test_backend_forwarder.py::test_forwarder_flush_retry_queue PASSED
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
============================== 45 passed in 12.78s ==============================
```
