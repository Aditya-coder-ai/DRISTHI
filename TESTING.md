# DRISTHI Central Backend & Database — Testing & Verification Strategy

## 1. Testing Philosophy
- **Zero Fabrication**: Tests must interact with real database connections (SQLite in-memory / file or PostgreSQL), real models, and real HTTP clients.
- **Continuous Validation**: Run automated tests after every small architectural addition.
- **Backward Compatibility**: Person 1's full test suite (61 tests) must remain 100% passing at all times.

---

## 2. Test Suites & Categorization

### A. Unit Tests (`backend/tests/unit/`)
- `test_schemas.py`: Pydantic schema validation, timestamps, duplicate keys, serialization.
- `test_adapters.py`: Normalization from Person 1 `SecurityEvent` to internal `AttackEventPayload`.
- `test_mitre_classifier.py`: Rule-based ATT&CK classification logic, evidence string validation, confidence scores.
- `test_sanitization.py`: Password redaction, sensitive token stripping.

### B. Integration Tests (`backend/tests/integration/`)
- `test_database_persistence.py`: SQLAlchemy session lifecycle, CRUD operations, transactions, rollbacks on error.
- `test_deduplication.py`: Submitting the exact same `event_id` multiple times must not create duplicate records.
- `test_session_lifecycle.py`: Active session grouping by IP/asset, timeout transitions, service tracking.
- `test_attacker_aggregation.py`: Aggregating commands, attempted usernames, and risk scores.

### C. API & Route Tests (`backend/tests/api/`)
- `test_health_api.py`: Verify `GET /api/health` reports status, database connectivity, and counts.
- `test_ingestion_api.py`: Verify `POST /api/events` and `POST /api/ingestion/events` with valid payloads, malformed JSON, and authorization checks.
- `test_events_query_api.py`: Verify filtering by service, severity, event type, date range, pagination boundaries.
- `test_attackers_api.py`: Verify attacker list and detail views.
- `test_sessions_api.py`: Verify session list and detail views.
- `test_dashboard_api.py`: Verify `GET /api/dashboard/stats`, `/timeline`, `/services` compute real aggregated values.
- `test_websocket_stream.py`: Verify `/ws/events` handshake, real-time broadcasts on ingestion, client disconnect resilience.

### D. Live End-to-End Inter-Service Tests (`backend/tests/e2e/`)
- `test_collector_to_backend_e2e.py`: Person 1's `CollectorDaemon` and `EventForwarder` transmitting live batches to the FastAPI backend, verifying end-to-end database persistence and status updates.

---

## 3. Running Tests
Run the entire suite with:
```powershell
.venv\Scripts\python.exe -m pytest tests/ backend/tests/ -v
```

