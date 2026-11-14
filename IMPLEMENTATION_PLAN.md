# DRISTHI Central Backend & Database — Phased Implementation Plan

## Overview
This document specifies the phased delivery roadmap for the Central Backend & Database Layer (Person 2).

### Phase 0: Repository Audit & Verification (COMPLETED)
- Inspect folder structure, existing honeypots, event generation, collector forwarder.
- Verify environment and all 61 existing tests passing.
- Document event contract and communication patterns.

### Phase 1: Target Architecture & Project Harness (IN PROGRESS)
- Establish harness documents: `AGENTS.md`, `ARCHITECTURE.md`, `IMPLEMENTATION_PLAN.md`, `TASKS.md`, `DECISIONS.md`, `API_CONTRACT.md`, `DATABASE_SCHEMA.md`, `TESTING.md`.
- Layout modular backend directory in `backend/app/`.

### Phase 2: Database Layer & Entity Models
- Implement SQLAlchemy 2.0 models: `AttackEvent`, `AttackerSession`, `AttackerProfile`, `MitreMapping`.
- Support PostgreSQL (with JSONB dialect) and SQLite fallback for local test execution.
- Create Alembic migration harness and initial revision script.
- Connection pooling and session lifecycle management.

### Phase 3: Central Event Ingestion Pipeline & Adapters
- Ingestion routes: `POST /api/events` and `POST /api/ingestion/events`.
- Authentication via `BACKEND_API_KEY` (Bearer / header).
- Ingestion adapters for Person 1's `SecurityEvent` schema and generic platform schemas.
- Ingestion service: validation, deduplication, timestamp normalization, transaction safety.

### Phase 4: Attacker Session & Behavioral Profile Management
- Session manager: state transitions (`active`, `idle`, `closed`), `first_seen`, `last_seen`, `services_accessed`.
- Attacker profiler: tracks unique IPs, attempted usernames, commands executed, risk score.
- Credential protection: redaction of raw passwords in all persistence and telemetry.

### Phase 5: MITRE ATT&CK Mapping Engine
- Modular evidence-based mapping engine:
  - `T1110.001` (Brute Force / Password Guessing)
  - `T1078` (Valid Accounts / Bait Credential Trigger)
  - `T1059` (Command and Scripting Interpreter)
  - `T1083` (File and Directory Discovery)
  - `T1048` (Exfiltration Over Alternative Protocol)
  - `T1046` (Network Service Scanning / Recon)
- Strict evidence attachment: event IDs, confidence score, mapping rationale.

### Phase 6: REST API Development
- `GET /api/health`: system status, DB connectivity, metrics.
- `GET /api/events` & `GET /api/events/{id}`: filtering by service, severity, event_type, IP, date range; pagination.
- `GET /api/attackers` & `GET /api/attackers/{id}`: list and detail views.
- `GET /api/sessions` & `GET /api/sessions/{id}`: list and detail views.
- `GET /api/dashboard/stats`, `/timeline`, `/services`: 100% database-derived analytics.
- CORS middleware configured for frontend dashboard.

### Phase 7: Real-Time Telemetry via WebSockets
- WebSocket endpoint `/ws/events`.
- Connection manager with broadcast channels, heartbeats, disconnect tolerance.
- Event sanitization before streaming.

### Phase 8: Automated Test Suite & Integration Verification
- Comprehensive pytest suite:
  - Unit tests: schema, adapters, MITRE engine, sanitization.
  - Integration tests: database persistence, session transitions, deduplication.
  - API tests: all endpoints, filtering, pagination, auth errors, validation errors.
  - E2E tests: connecting Person 1's `EventForwarder` and `CollectorDaemon` to the running FastAPI backend.

### Phase 9: Final Acceptance & Engineering Report
- Verify all acceptance criteria.
- Produce comprehensive final engineering report.

