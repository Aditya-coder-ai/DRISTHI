# FTP Deception Service (Phase 2)

## Overview
The FTP Deception Service simulates an offsite corporate backup repository node (`Corp-Storage-Node-02`, representing `10.0.1.30:2121` advertised in the Phase 1 SSH server notes).

It is built as a controlled, asynchronous RFC 959 FTP honeypot strictly isolated by an in-memory / virtual filesystem (VFS).

## Key Features
- **Virtual Filesystem (VFS) Jail**: Zero host OS access. Path traversal attacks (`..`, `C:\`, `/etc/passwd`) are clamped to virtual root (`/`) and strictly prevented from accessing host system storage.
- **Decoy Assets**: Contains believable corporate and backup files:
  - `backups/finance/customer_database.sql` (MySQL dump of customer and invoice records)
  - `backups/finance/backup.zip` (Valid archive with backup manifests and schema snapshots)
  - `backups/finance/db_migration_notes.txt` (Lateral movement breadcrumbs pointing to `10.0.1.25:5432` and `database_root:DBroot@2026`)
  - `corporate/employee_records.csv` (Corporate personnel roster)
  - `corporate/financial_report.xlsx` (OpenXML financial workbook)
- **Bait Credentials**: Configured with decoy credential `backup_user:Backup@2026`. Usage immediately tags events with `bait_credential_triggered: true` and `alert_priority: "HIGH"`.
- **Passive Data Transfer**: Full RFC 959 passive mode support for directory listings (`LIST`, `NLST`), file downloads (`RETR`), and file uploads (`STOR`).
- **Telemetry & Normalization**: Translates raw FTP interactions into unified `SecurityEvent` schema payloads (`asset_id: ftp-001`).

## Directory Structure
```text
services/ftp/
├── config/
│   └── ftp_config.json        # Port, banner, and user credentials
├── decoy_root/                # Decoy directory tree exposed to attackers
│   ├── README.txt
│   ├── backups/
│   │   └── finance/
│   │       ├── backup.zip
│   │       ├── customer_database.sql
│   │       └── db_migration_notes.txt
│   └── corporate/
│       ├── employee_records.csv
│       └── financial_report.xlsx
├── uploads/                   # Quarantined uploads directory
├── vfs.py                     # Virtual Filesystem with traversal protection
├── server.py                  # Asynchronous RFC 959 FTP Honeypot server
├── runner.py                  # Service lifecycle manager (run, start, stop, status)
├── ftp_event_adapter.py       # Raw FTP telemetry to SecurityEvent adapter
└── README.md
```

## Running the Service

### Foreground Mode
```powershell
.venv\Scripts\python.exe services/ftp/runner.py run --port 2121 --host 0.0.0.0
```

### Background Daemon Mode
```powershell
# Start daemon
.venv\Scripts\python.exe services/ftp/runner.py start

# Check status
.venv\Scripts\python.exe services/ftp/runner.py status

# Stop daemon
.venv\Scripts\python.exe services/ftp/runner.py stop
```

## Testing & Simulation

Run automated tests:
```powershell
.venv\Scripts\python.exe -m pytest tests/test_ftp_vfs.py tests/test_ftp_adapter.py tests/test_ftp_deception.py -v
```

Run adversary simulation:
```powershell
.venv\Scripts\python.exe scripts/simulate_ftp_attack.py
```

