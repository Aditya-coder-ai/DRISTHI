# DRISTHI Central Backend & Database Architecture

## 1. System Architecture Diagram

```text
+-----------------------------------------------------------------------------------+
|                        DECEPTION ASSETS LAYER (Person 1)                          |
|                                                                                   |
|  [SSH Honeypot]     [FTP Honeypot]     [Web Admin Portal]   [Fake DB Honeypot]    |
|   (Port 2222)        (Port 2121)          (Port 8080)       (PG 5432 / MySQL 3306)|
|        |                  |                    |                     |            |
|  [CowrieAdapter]    [FTPAdapter]         [WebAdapter]          [DBAdapter]        |
|        +------------------+--------------------+---------------------+            |
|                                     |                                             |
|                              SecurityEvent                                        |
|                                     v                                             |
|                     [Collector Daemon & Retry Queue]                              |
|                          (SQLite backoff buffer)                                  |
+-------------------------------------+---------------------------------------------+
                                      | HTTP POST (JSON batch)
                                      | Auth: Bearer / X-API-Key
                                      v
+-----------------------------------------------------------------------------------+
|                     CENTRAL BACKEND LAYER (Person 2 - This Module)                |
|                                                                                   |
|  FastAPI Application (Port 8000)                                                  |
|  ├── Ingestion Engine (POST /api/events, POST /api/ingestion/events)              |
|  │   ├── Token Authentication & Secret Verification                               |
|  │   ├── Schema Validation & Normalization Pipeline                               |
|  │   ├── Deduplication Layer (event_id cache & DB unique constraint)              |
|  │   ├── Ingestion Adapters (Person 1 SecurityEvent & Generic Event Schemas)      |
|  │   └── MITRE ATT&CK Mapping Engine (Evidence-based classification)              |
|  │                                                                                |
|  ├── Attacker Session & Profile Manager                                           |
|  │   ├── Session State Machine (active, idle, closed, escalated)                  |
|  │   ├── IP & Asset Heuristic Clustering                                          |
|  │   └── Attacker Behavioral Profile Aggregator                                   |
|  │                                                                                |
|  ├── Persistence & Storage (SQLAlchemy 2.0 + Alembic)                             |
|  │   ├── attack_events (normalized telemetry with JSONB metadata)                 |
|  │   ├── attacker_sessions (stateful lifecycle tracking)                          |
|  │   ├── attacker_profiles (threat actors, commands, usernames, MITRE tags)       |
|  │   └── mitre_mappings (evidence-linked ATT&CK matrix mappings)                  |
|  │                                                                                |
|  ├── REST API Endpoints                                                           |
|  │   ├── GET /api/health (Database & WebSocket readiness)                        |
|  │   ├── GET /api/events, /api/events/{id} (Pagination, filtering, sorting)       |
|  │   ├── GET /api/attackers, /api/attackers/{id}                                  |
|  │   ├── GET /api/sessions, /api/sessions/{id}                                    |
|  │   └── GET /api/dashboard/stats, /timeline, /services                           |
|  │                                                                                |
|  └── Real-Time Telemetry Layer                                                    |
|      └── WebSocket Manager (/ws/events) broadcast channel                         |
+-------------------------------------+---------------------------------------------+
                                      | WebSocket / REST
                                      v
+-----------------------------------------------------------------------------------+
|                        FRONTEND DASHBOARD (Person 4)                              |
|                     React + TypeScript + Tailwind UI                              |
+-----------------------------------------------------------------------------------+
```

## 2. Ingestion Pipeline Data Flow

1. **Ingest**: Collector daemon or individual decoys POST batches of `SecurityEvent` JSON payloads.
2. **Authenticate**: Ingestion route checks `X-API-Key` or `Authorization: Bearer <token>`.
3. **Validate & Deduplicate**: Events are parsed into Pydantic models. Any event whose `event_id` is already stored is skipped without error.
4. **Normalize**: Map protocol-specific telemetry to database schema, computing severity (`low`, `medium`, `high`, `critical`) based on canary hits, bait credentials, brute force, or suspicious commands.
5. **MITRE ATT&CK Tagging**: Rule-based detection attaches evidence-supported MITRE technique IDs (e.g., `T1110.001` Password Guessing, `T1059` Command Shell, `T1083` File Discovery, `T1078` Valid Accounts).
6. **Session & Attacker Update**:
   - Locate active session for `(source_ip, asset_id)` or create new session.
   - Increment event count, append accessed services, update `last_seen`.
   - Update `attacker_profiles` aggregate (observed commands, attempted usernames, highest severity).
7. **Persist**: Atomically commit event, session, profile, and MITRE records in a single database transaction.
8. **Broadcast**: Push sanitized real-time JSON payload to active WebSocket clients on `/ws/events`.

