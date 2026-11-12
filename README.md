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
│   ├── ftp/                     # Phase 2: Fake FTP Server (Pending)
│   ├── web/                     # Phase 3: Fake Web Admin Portal (Pending)
│   └── database/                # Phase 4: Fake Database (Pending)
├── credentials/                 # Phase 5: Bait Credentials Management
│   └── decoy_credentials.json
├── collector/                   # Phase 6: Event Collection & Normalization
│   ├── normalizer.py
│   └── event_collector.py
├── shared/                      # Shared Models & Utilities
│   ├── event_schema.py          # Unified SecurityEvent schema
│   ├── config.py                # Environment configuration
│   └── logger.py                # Structured logging
├── tests/                       # Automated Verification Suite
│   ├── test_event_schema.py
│   ├── test_ssh_adapter.py
│   └── test_ssh_deception.py
├── scripts/                     # Adversary Simulation Scripts
│   └── simulate_ssh_attack.py
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

---

## Quickstart

### 1. Installation
```powershell
uv venv .venv --python 3.12
.venv\Scripts\activate
uv pip install -r requirements.txt
```

### 2. Run Tests
```powershell
.venv\Scripts\python.exe -m pytest tests/ -v
```

### 3. Run Adversary Simulation
```powershell
# In terminal 1: Start SSH Honeypot
.venv\Scripts\python.exe services/ssh/runner.py run --port 2222 --host 127.0.0.1

# In terminal 2: Run Attack Simulation
.venv\Scripts\python.exe scripts/simulate_ssh_attack.py
```
