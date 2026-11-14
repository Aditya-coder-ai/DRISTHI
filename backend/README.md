# DRISTHI — Central Backend & Database Layer (Person 2 Module)

## Overview
The **DRISTHI Central Backend** serves as the central command, persistence, and telemetry correlation core of the platform.
It ingests normalized deception events from all distributed honeypots (SSH, FTP, Web Admin, Database), maintains stateful attacker sessions, aggregates behavioral profiles, correlates evidence with the MITRE ATT&CK matrix, persists records in PostgreSQL (with SQLite fallback), and exposes real-time WebSocket feeds and high-performance REST APIs to the React dashboard.

---

## Key Capabilities

1. **High-Throughput Central Ingestion**:
   - `POST /api/events` and `POST /api/ingestion/events`
   - Native compatibility with Person 1's `SecurityEvent` batches emitted by `collector/forwarder.py` and `collector/daemon.py`.
   - Idempotent deduplication by `event_id` UUID.
2. **Relational Persistence**:
   - PostgreSQL with JSONB indexing and fallback to SQLite for local standalone development.
   - Alembic database migration suite (`alembic upgrade head`).
3. **Stateful Attacker Session Tracking**:
   - Groups interactions by IP and temporal activity window (`SESSION_IDLE_TIMEOUT_SECONDS`).
   - Tracks accessed services, event counts, and lifecycle transitions (`active`, `idle`, `closed`, `escalated`).
4. **Behavioral Attacker Profiling**:
   - Aggregates attempted usernames, executed commands, targeted assets, and dynamic risk scoring per unique observed source IP.
5. **Evidence-Based MITRE ATT&CK Mapping**:
   - Maps events to technique IDs (`T1110.001`, `T1078`, `T1059.004`, `T1083`, `T1048`, `T1046`, `T1082`, `T1021.004`) based on verifiable payload evidence.
6. **Real-Time WebSockets**:
   - `/ws/events` stream pushes sanitized events to connected dashboard instances.
7. **Production Security**:
   - Credential redaction (`password_length` retained, raw passwords sanitized).
   - SQL injection immunity via parameterized SQLAlchemy ORM.
   - Configurable CORS and rate limiting.

---

## Directory Layout
```text
backend/
├── app/
│   ├── main.py                # FastAPI application entrypoint & lifespan
│   ├── core/                  # Configuration, logging, security, exceptions
│   ├── database/              # SQLAlchemy engine, sessionmaker, declarative base
│   ├── models/                # AttackEvent, AttackerSession, AttackerProfile, MitreMapping
│   ├── schemas/               # Pydantic request/response schemas
│   ├── integrations/          # Adapters for Person 1 SecurityEvent & SSH/FTP telemetry
│   ├── services/              # IngestionService, SessionService, AttackerService, MitreService, AnalyticsService
│   ├── websocket/             # WebSocketManager real-time pub/sub
│   └── api/                   # REST route handlers & dependency injection
├── alembic/                   # Database migrations
├── tests/                     # Unit, Integration, API, and End-to-End test suite
├── alembic.ini
├── requirements.txt
├── .env.example
└── README.md
```

---

## Quickstart Instructions

### 1. Run Database Migrations
```powershell
python -m alembic upgrade head
```

### 2. Start Central Backend Server
```powershell
python backend/app/main.py
```
Or with Uvicorn:
```powershell
python -m uvicorn backend.app.main:app --host 0.0.0.0 --port 8000
```
Interactive Swagger API documentation will be available at: `http://localhost:8000/docs`

### 3. Run Automated Tests
```powershell
python -m pytest backend/tests/ -v
```

