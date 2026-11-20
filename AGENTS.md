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
   - Zero hardcoded credentials, API tokens, or provider-prefixed secret literals (such as `whsec_`, `sk_live_`, `ghp_`, or real PEM keys) anywhere in source code, docstrings, or test fixtures.
   - Load all signing secrets (including `STRIPE_WEBHOOK_SECRET` and `BACKEND_API_KEY`) strictly from environment variables via `pydantic-settings`; fail closed if required production secrets are missing or set to template placeholders.
   - Use clearly synthetic, non-provider-prefixed test secrets isolated via `monkeypatch` in automated tests; never log secrets or include secret values in exceptions or API responses.
   - Keep `.env`, `.env.*`, local databases, private keys, and runtime logs excluded via `.gitignore`; preserve safe `.env.example` templates with non-usable placeholder values.
   - Maintain passing GitHub Actions CI (`.github/workflows/ci.yml`) and security scanning (`.github/workflows/security.yml`) checks on all pull requests.
   - Structured JSON logging.
   - Graceful WebSocket client disconnects without impacting REST API.

