# DRISTHI — Agent Guidelines & Engineering Standards

## 1. Project Overview
**DRISTHI** is an Adaptive Distributed Cyber Deception Platform using Reinforcement Learning.
- **Person 1 Domain**: Deception Assets, HoneyFS, Bait Credentials, Canary Detection, and Forwarder Daemon.
- **Person 2 Domain (This Module)**: Central Backend, Relational Persistence (PostgreSQL/SQLAlchemy), Session Management, Attacker Profiling, REST APIs, WebSockets, and MITRE ATT&CK integration.
- **Person 3 Domain**: Threat Detection & Intelligence, RL Policy Engine.
- **Person 4 Domain**: Frontend Dashboard & Visualization.

## 2. Agent Responsibilities & Rules
1. **Preserve Person 1 Implementation**: Never modify, break, or refactor Person 1's honeypot services, adapters, or tests. All changes to contracts must be backward-compatible adapters.
2. **Harness & Loop Engineering**:
   - Continuous cycle: *Inspect -> Plan -> Implement -> Test -> Evaluate -> Fix -> Improve -> Repeat*.
   - Never mark a task complete without automated test verification.
   - Maintain engineering documentation (`TASKS.md`, `ARCHITECTURE.md`, `API_CONTRACT.md`, `DATABASE_SCHEMA.md`, `DECISIONS.md`, `TESTING.md`).
3. **Data Integrity & Security**:
   - Redact passwords and credentials in all logs and dashboard APIs (`password_length` only).
   - Reject malformed or unauthorized telemetry.
   - Idempotent event processing by `event_id` (UUID).
   - Parameterized queries via SQLAlchemy ORM (zero SQL injection).
   - Strict UTC ISO 8601 timestamps.
4. **Resilience & Production Standards**:
   - Zero hardcoded credentials.
   - Configurable environment via `pydantic-settings`.
   - Structured JSON logging.
   - Graceful WebSocket client disconnects without impacting REST API.

