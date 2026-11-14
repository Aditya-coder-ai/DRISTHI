# Database Deception Service (Phase 4)

## Overview
The Database Deception Service simulates an enterprise relational database cluster (**Apex Primary Relational Cluster**, representing `db-cluster.corp.internal` on ports `5432` for PostgreSQL and `3306` for MySQL).

It is built as an asynchronous protocol simulator that interacts with real database clients (`psql`, `mysql`, Python drivers, DBeaver, Nmap) while enforcing absolute isolation: **no real database engine or host storage is ever touched**.

## Key Features
- **PostgreSQL v3.0 Protocol Engine (Port 5432)**:
  - Handles `SSLRequest` negotiation and cleartext authentication.
  - Implements `AuthenticationCleartextPassword`, `AuthenticationOk`, `ParameterStatus`, and `ReadyForQuery`.
  - Parses and responds to `Simple Query` (`'Q'`) with `RowDescription` and `DataRow` streams.
- **MySQL Client/Server Protocol Engine (Port 3306)**:
  - Handshake protocol v10 (`8.0.35-Apex-Cluster`).
  - Supports `HandshakeResponse41`, `OK_Packet`, `ERR_Packet`.
  - Handles `COM_QUERY`, `COM_INIT_DB`, `COM_PING`, `COM_QUIT`.
- **Fictional Corporate Datasets**:
  - `corporate_finance`: `general_ledger`, `budget_allocations`, `quarterly_earnings`
  - `customer_accounts`: `clients`, `invoices`, `credit_limits`
  - `employee_records`: `personnel`, `access_roster`
  - `payroll_2026`: `executive_compensation`, `direct_deposits`
  - `transaction_history`: `wire_transfers`, `interbank_settlements`
- **Lateral Breadcrumbs & Bait Credentials**:
  - Planted credentials: `database_root:DBroot@2026`.
  - Host references pointing to `finance-server.corp.internal`, `Corp-Storage-Node-02`, and `web-admin.corp.internal`.
- **Security & Password Protection**:
  - Passwords are never stored in plaintext in security telemetry (redacted to `password_length`).
  - Normalized directly to `SecurityEvent` schema with `asset_id: db-001`.

## Directory Structure
```text
services/database/
├── data/
│   └── seed_db.py              # In-memory tables, schemas, and query simulation
├── postgres_server.py          # Asynchronous PostgreSQL v3.0 protocol honeypot
├── mysql_server.py             # Asynchronous MySQL protocol honeypot
├── db_event_adapter.py         # Telemetry normalizer to SecurityEvent (db-001)
├── runner.py                   # Service lifecycle CLI (run, start, stop, status)
└── README.md
```

## Running the Service

### Foreground Mode
```powershell
.venv\Scripts\python.exe services/database/runner.py run --host 0.0.0.0 --pg-port 5432 --mysql-port 3306
```

### Background Daemon Mode
```powershell
# Start daemon
.venv\Scripts\python.exe services/database/runner.py start

# Check status
.venv\Scripts\python.exe services/database/runner.py status

# Stop daemon
.venv\Scripts\python.exe services/database/runner.py stop
```

## Running Tests
```powershell
.venv\Scripts\python.exe -m pytest tests/test_database_deception.py -v
```

