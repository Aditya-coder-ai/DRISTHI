# SSH Deception Service (Phase 1)

## Overview
The SSH Deception Service implements high-fidelity deception simulating a Linux production server (`finance-server`). It is built on top of **Cowrie**, running in a strictly controlled simulated shell environment that captures adversary interactions without exposing the underlying host operating system.

## Key Features
- **Simulated Linux Environment**: Emulates Ubuntu 22.04 LTS host `finance-server`.
- **HoneyFS Overlays**: Believable directory and file structures (`/etc/hosts`, `/etc/passwd`, `/etc/shadow`, `/home/finance_admin/.bash_history`, `/var/financial_data/`).
- **Bait Credentials**: Configured with decoy credential `finance_admin:Finance@2026` matching Phase 5 specifications, plus breadcrumb notes pointing toward decoy FTP, Web Admin, and Database assets.
- **Activity Capture**: Records connection, authentication attempts, command executions, and file transfers.
- **Event Normalization**: Transforms Cowrie raw JSON telemetry into unified `SecurityEvent` schema (`asset_id: ssh-001`).
- **Security Isolation**: Uses simulated shell only; no real host shell access is possible. Cleartext passwords are redacted from security events.

## Configuration
Configuration files are located in `services/ssh/config/`:
- `cowrie.cfg`: Server and logging settings.
- `userdb.txt`: Credential authorization rules and decoy accounts.
- `honeyfs/`: Overlaid realistic files.

## Running the Service

### Foreground Mode
```bash
.venv\Scripts\python.exe services/ssh/runner.py run --port 2222 --host 0.0.0.0
```

### Background Daemon Mode
```bash
# Start daemon
.venv\Scripts\python.exe services/ssh/runner.py start

# Check status
.venv\Scripts\python.exe services/ssh/runner.py status

# Stop daemon
.venv\Scripts\python.exe services/ssh/runner.py stop
```

## Testing & Simulation
Run automated tests:
```bash
.venv\Scripts\python.exe -m pytest tests/ -v
```

Run simulated attack interaction:
```bash
.venv\Scripts\python.exe scripts/simulate_ssh_attack.py
```

