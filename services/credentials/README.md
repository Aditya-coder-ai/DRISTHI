# Dynamic Bait Credentials & Canaries (Phase 5)

## Overview
The Bait Credentials Registry provides centralized management, canary triggering, and cross-service lateral movement detection across all deception assets.

It ensures consistent decoy identities are maintained across SSH, FTP, Web, and Database nodes while detecting when an attacker exfiltrates credentials from one honeypot and attempts to reuse them elsewhere.

## Key Features
- **Centralized Credential Lifecycle**:
  - Maintains bait accounts in `credentials/decoy_credentials.json`.
  - Tracks state: `ACTIVE`, `TRIGGERED`, `ROTATED`, `EXPOSED`.
  - Stores SHA-256 cryptographic hashes for credential verification.
- **Canary Triggering (`CANARY_TRIGGERED`)**:
  - Emits critical security events whenever a registered decoy credential is used.
  - Records timestamp, target asset, source IP, and interaction method.
- **Cross-Service Lateral Reuse Detection (`CREDENTIAL_REUSE`)**:
  - Correlates the `origin_asset` where a credential was planted (e.g. `ssh-001` or `ftp-001`) with the `target_asset` where it was subsequently used (e.g. `db-001`).
  - Automatically raises `CREDENTIAL_REUSE` alert with attack stage flagged as *Lateral Movement*.
- **Dynamic Rotation**:
  - Supports rotating credentials without disrupting active services.
  - Maintains previous credential records in `ROTATED` state.

## Default Bait Accounts

| Username | Decoy Password | Origin Asset | Planted Locations | Description |
|---|---|---|---|---|
| `finance_admin` | `Finance@2026` | `ssh-001` | `.bash_history`, Web config | Linux SSH bastion operator |
| `backup_user` | `Backup@2026` | `ftp-001` | FTP `/backups`, Web config | Offsite storage replication daemon |
| `database_root` | `DBroot@2026` | `db-001` | FTP migration notes, Web config | Relational cluster superuser |
| `admin` | `Apex@2026!` | `web-001` | Web admin login | Web management portal admin |

## Usage in Code
```python
from services.credentials.registry import global_registry

# Evaluate an incoming interaction
is_bait, canary_event, reuse_event = global_registry.evaluate_interaction(
    username="database_root",
    password_attempt="DBroot@2026",
    target_asset="db-001",
    src_ip="192.168.1.100",
    protocol="DATABASE",
)
```
