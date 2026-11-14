# DRISTHI Central Database Schema Specification

## 1. Relational Entity Overview

```text
+--------------------------------------------------------------------------------+
|                             DATABASE TABLES                                    |
|                                                                                |
|  +--------------------+        +---------------------+                         |
|  | attacker_profiles  |<-------|  attacker_sessions  |                         |
|  +--------------------+ 1    N +---------------------+                         |
|  | PK attacker_id     |        | PK session_id       |                         |
|  |    source_ip (UQ)  |        | FK attacker_id      |                         |
|  |    first_seen      |        |    source_ip        |                         |
|  |    last_seen       |        |    first_seen       |                         |
|  |    total_events    |        |    last_seen        |                         |
|  |    highest_severity|        |    services_accessed|                         |
|  |    behaviors (JSON)|        |    event_count      |                         |
|  +--------------------+        |    status           |                         |
|                                +---------------------+                         |
|                                           | 1                                  |
|                                           |                                    |
|                                           | N                                  |
|                                +---------------------+                         |
|                                |    attack_events    |                         |
|                                +---------------------+                         |
|                                | PK event_id (UUID)  |                         |
|                                | FK session_id       |                         |
|                                |    source_ip        |                         |
|                                |    source_port      |                         |
|                                |    source_service   |                         |
|                                |    asset_id         |                         |
|                                |    event_type       |                         |
|                                |    timestamp        |                         |
|                                |    username         |                         |
|                                |    severity         |                         |
|                                |    status           |                         |
|                                |    activity (JSONB) |                         |
|                                |    metadata (JSONB) |                         |
|                                |    created_at       |                         |
|                                +---------------------+                         |
|                                           | 1                                  |
|                                           |                                    |
|                                           | N                                  |
|                                +---------------------+                         |
|                                |   mitre_mappings    |                         |
|                                +---------------------+                         |
|                                | PK id               |                         |
|                                | FK event_id         |                         |
|                                |    technique_id     |                         |
|                                |    technique_name   |                         |
|                                |    confidence       |                         |
|                                |    evidence         |                         |
|                                |    created_at       |                         |
|                                +---------------------+                         |
+--------------------------------------------------------------------------------+
```

---

## 2. Table Definitions

### Table: `attack_events`
- `event_id` (VARCHAR(64), Primary Key, Unique, Indexed)
- `session_id` (VARCHAR(64), Foreign Key $\to$ `attacker_sessions.session_id`, Nullable, Indexed)
- `source_ip` (VARCHAR(64), Not Null, Indexed)
- `source_port` (INTEGER, Nullable)
- `source_service` (VARCHAR(32), Not Null, Indexed) — e.g., "ssh", "ftp", "web", "database"
- `asset_id` (VARCHAR(64), Not Null, Indexed) — e.g., "ssh-001", "ftp-001"
- `event_type` (VARCHAR(64), Not Null, Indexed) — e.g., "command_execution", "login_failed"
- `username` (VARCHAR(128), Nullable, Indexed)
- `severity` (VARCHAR(16), Not Null, Indexed) — "low", "medium", "high", "critical"
- `status` (VARCHAR(32), Not Null) — "success", "failed", "executed", "attempt", "detected"
- `timestamp` (TIMESTAMP WITH TIME ZONE, Not Null, Indexed)
- `activity` (JSONB / JSON, Not Null, Default `{}`) — captured details (commands, files, queries)
- `metadata` (JSONB / JSON, Not Null, Default `{}`) — contextual service metadata
- `created_at` (TIMESTAMP WITH TIME ZONE, Not Null, Default `CURRENT_TIMESTAMP`)

**Indexes:**
- `ix_attack_events_timestamp` ON `attack_events (timestamp DESC)`
- `ix_attack_events_source_ip` ON `attack_events (source_ip)`
- `ix_attack_events_service` ON `attack_events (source_service)`
- `ix_attack_events_severity` ON `attack_events (severity)`
- `ix_attack_events_session_id` ON `attack_events (session_id)`
- Composite: `ix_events_service_severity_time` ON `attack_events (source_service, severity, timestamp DESC)`

---

### Table: `attacker_sessions`
- `session_id` (VARCHAR(64), Primary Key, Indexed)
- `attacker_id` (VARCHAR(64), Foreign Key $\to$ `attacker_profiles.attacker_id`, Nullable, Indexed)
- `source_ip` (VARCHAR(64), Not Null, Indexed)
- `first_seen` (TIMESTAMP WITH TIME ZONE, Not Null)
- `last_seen` (TIMESTAMP WITH TIME ZONE, Not Null, Indexed)
- `services_accessed` (JSONB / JSON, Not Null, Default `[]`) — list of unique services
- `event_count` (INTEGER, Not Null, Default 1)
- `status` (VARCHAR(16), Not Null, Default "active", Indexed) — "active", "idle", "closed", "escalated"
- `created_at` (TIMESTAMP WITH TIME ZONE, Not Null, Default `CURRENT_TIMESTAMP`)
- `updated_at` (TIMESTAMP WITH TIME ZONE, Not Null, Default `CURRENT_TIMESTAMP`)

---

### Table: `attacker_profiles`
- `attacker_id` (VARCHAR(64), Primary Key)
- `source_ip` (VARCHAR(64), Unique, Not Null, Indexed)
- `first_seen` (TIMESTAMP WITH TIME ZONE, Not Null)
- `last_seen` (TIMESTAMP WITH TIME ZONE, Not Null, Indexed)
- `total_events` (INTEGER, Not Null, Default 0)
- `total_sessions` (INTEGER, Not Null, Default 0)
- `highest_severity` (VARCHAR(16), Not Null, Default "low")
- `attempted_usernames` (JSONB / JSON, Not Null, Default `[]`)
- `attempted_commands` (JSONB / JSON, Not Null, Default `[]`)
- `services_targeted` (JSONB / JSON, Not Null, Default `[]`)
- `risk_score` (FLOAT, Not Null, Default 0.0)
- `created_at` (TIMESTAMP WITH TIME ZONE, Not Null, Default `CURRENT_TIMESTAMP`)
- `updated_at` (TIMESTAMP WITH TIME ZONE, Not Null, Default `CURRENT_TIMESTAMP`)

---

### Table: `mitre_mappings`
- `id` (INTEGER, Primary Key, Autoincrement)
- `event_id` (VARCHAR(64), Foreign Key $\to$ `attack_events.event_id`, Not Null, Indexed)
- `technique_id` (VARCHAR(32), Not Null, Indexed) — e.g., "T1110.001", "T1059.004"
- `technique_name` (VARCHAR(128), Not Null)
- `tactic` (VARCHAR(64), Not Null) — e.g., "Credential Access", "Execution"
- `confidence` (FLOAT, Not Null) — 0.0 to 1.0
- `evidence` (TEXT, Not Null) — rationale and triggering tokens
- `created_at` (TIMESTAMP WITH TIME ZONE, Not Null, Default `CURRENT_TIMESTAMP`)

