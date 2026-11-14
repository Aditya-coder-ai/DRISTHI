# DRISTHI Central Backend & Database Task Checklist

- [x] **Phase 0 — Repository Audit & Setup**
  - [x] Clone/inspect workspace and repository structure.
  - [x] Resolve Python 3.12 environment and sandboxed execution wrapper (`powershell.cmd`).
  - [x] Run and verify existing 61 tests across all Person 1 deception services (100% passing).
  - [x] Document event schemas and communication interfaces between Person 1 and Person 2.

- [x] **Phase 1 — Harness Engineering Documentation**
  - [x] Create/maintain `AGENTS.md`
  - [x] Create/maintain `ARCHITECTURE.md`
  - [x] Create/maintain `IMPLEMENTATION_PLAN.md`
  - [x] Create/maintain `TASKS.md`
  - [x] Create/maintain `DECISIONS.md`
  - [x] Create/maintain `API_CONTRACT.md` (v2.0)
  - [x] Create/maintain `DATABASE_SCHEMA.md`
  - [x] Create/maintain `TESTING.md`

- [x] **Phase 2 — Database Models & Migrations**
  - [x] Implement SQLAlchemy 2.0 engine, SessionLocal, and DeclarativeBase in `backend/app/database/`.
  - [x] Implement `AttackEvent` entity model with JSONB/JSON support and query indexes.
  - [x] Implement `AttackerSession` entity model with foreign key relationships.
  - [x] Implement `AttackerProfile` entity model with aggregate behavioral fields.
  - [x] Implement `MitreMapping` entity model with evidence tracking.
  - [x] Configure Alembic migrations (`alembic.ini`, `env.py`, `versions/0001_initial_schema.py`).
  - [x] Verify migration upgrade and downgrade cycles on clean database.

- [x] **Phase 3 — Central Event Ingestion Engine**
  - [x] Implement ingestion schemas in `backend/app/schemas/event.py`.
  - [x] Implement service authentication (`APIKeyHeader` / `BearerToken`) in `backend/app/core/security.py`.
  - [x] Implement `IngestionService` handling deduplication, normalization, and transactional commit.
  - [x] Implement Person 1 `SecurityEvent` adapter in `backend/app/integrations/person1_adapter.py`.
  - [x] Create endpoints: `POST /api/events`, `POST /api/ingestion/events`, `POST /api/ingest`.

- [x] **Phase 4 — Attacker Session & Profile Management**
  - [x] Implement `SessionService` (detect active session by IP/asset, timeout thresholds, state transitions).
  - [x] Implement `AttackerService` (aggregate attempted usernames, commands, risk score).
  - [x] Implement credential redaction utilities (`backend/app/core/security.py`).

- [x] **Phase 5 — MITRE ATT&CK Mapping Engine**
  - [x] Implement rule-based MITRE classifier (`backend/app/services/mitre_service.py`).
  - [x] Map brute force (`T1110.001`), bait triggers (`T1078`), command execution (`T1059.004`), file access (`T1083`), exfiltration (`T1048`), discovery (`T1046`, `T1082`).
  - [x] Link technique mappings to stored events with confidence scores.

- [x] **Phase 6 — REST APIs & Analytical Dashboard Endpoints**
  - [x] Health check endpoint: `GET /api/health`.
  - [x] Event query endpoints: `GET /api/events` and `GET /api/events/{id}` with filtering and pagination (`page_size` and `limit` alias).
  - [x] Attacker profile endpoints: `GET /api/attackers` and `GET /api/attackers/{id}`.
  - [x] Session query endpoints: `GET /api/sessions` and `GET /api/sessions/{id}`.
  - [x] Dashboard analytics: `GET /api/dashboard/stats` (with `recent_events`), `/timeline`, `/services` (100% database-derived).
  - [x] CORS configuration (`FRONTEND_ORIGINS`) and OpenAPI documentation.

- [x] **Phase 7 — Real-Time WebSocket Streaming**
  - [x] Implement `WebSocketManager` in `backend/app/websocket/manager.py`.
  - [x] Implement `/ws/events` endpoint with connection management and heartbeat support.
  - [x] Stream sanitized real-time events to connected dashboard clients upon ingestion.

- [x] **Phase 8 — Automated Testing & Verification**
  - [x] Unit tests for schemas, adapters, MITRE classifier, credential redaction.
  - [x] Integration tests for database persistence, transactions, duplicate suppression.
  - [x] API tests for all endpoints, pagination, filtering, security/auth.
  - [x] Live integration test: Person 1's `EventForwarder` & `CollectorDaemon` posting to FastAPI backend with real DB persistence.
  - [x] Total suite: 96 passed / 96 tests (100% passing).

- [x] **Phase 9 — Frontend Readiness for Person 3**
  - [x] Add `limit` pagination alias to all query endpoints (`events`, `attackers`, `sessions`).
  - [x] Add `recent_events` list to `GET /api/dashboard/stats`.
  - [x] Add `/api/ingest` route alias.
  - [x] Configure dynamic `FRONTEND_ORIGINS` CORS environment variable.
  - [x] Add 7 new automated frontend-readiness tests.
  - [x] Publish `PERSON3_FRONTEND_INTEGRATION_GUIDE.md` and `PERSON2_BACKEND_READINESS_REPORT.md`.

- [x] **Phase 10 — System-Wide Health Check & Auto-Fix Verification**
  - [x] Verify all 22 backend modules import without error.
  - [x] Verify live FastAPI startup and runtime health endpoint.
  - [x] Verify PostgreSQL DDL schema compilation and SQLite persistence.
  - [x] Execute live FTP honeypot server, interact with real VFS, normalize and ingest real FTP telemetry into backend.
  - [x] Execute live SSH Cowrie log normalization and ingestion into backend.
  - [x] Test live WebSocket connections and ping-pong heartbeat.
  - [x] Unify platform `requirements.txt` with backend and deception dependencies.
  - [x] Update `Dockerfile` and `docker-compose.yml` to define the full stack including `central-backend`.
  - [x] Re-run complete 96-test automated suite (100% passing).
  - [x] Generate definitive `DRISTHI_COMPLETE_SYSTEM_HEALTH_REPORT.md`.
