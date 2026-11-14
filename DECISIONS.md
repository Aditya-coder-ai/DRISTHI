# DRISTHI Central Backend & Database — Architecture Decision Records (ADR)

## ADR 001: Dialect-Agnostic SQLAlchemy 2.0 ORM with PostgreSQL & SQLite Fallback
- **Context**: The production deployment of DRISTHI uses PostgreSQL for persistence with JSONB indexing. However, developer workstations, CI containers, and local tests may operate without a live external PostgreSQL server.
- **Decision**: Define models using SQLAlchemy 2.0 with type variants: `JSON().with_variant(postgresql.JSONB(), "postgresql")`. The database connection layer checks `DATABASE_URL`; if unconfigured or pointing to `sqlite`, it smoothly defaults to SQLite (`sqlite+pysqlite:///drishti.db` or in-memory for tests) while fully supporting PostgreSQL in production.
- **Consequence**: Zero configuration required for rapid local testing; production benefits from PostgreSQL JSONB operators,GIN indexes, and ACID guarantees.

## ADR 002: Dual-Schema Ingestion Compatibility (Person 1 + Generic Telemetry)
- **Context**: Person 1 implemented `SecurityEvent` (`asset_id`, `event_type`, `source_ip`, `protocol`, `timestamp`, `status`, `metadata`). The master prompt proposes a schema with `source_service`, `activity`, `severity`, etc.
- **Decision**: Provide an adapter pattern in the ingestion engine. The ingestion routes (`POST /api/events` and `POST /api/ingestion/events`) accept both Person 1's `SecurityEvent` array, single `SecurityEvent` objects, and generic normalized events, normalizing them transparently to the internal persistence model.
- **Consequence**: Full backward compatibility with Person 1's existing honeypots and collector daemon without altering any of their code or tests.

## ADR 003: Idempotent Ingestion via UUID Event ID Deduplication
- **Context**: Person 1's `EventForwarder` and `RetryQueue` implement at-least-once delivery with retries upon network timeout.
- **Decision**: Every event is validated for a unique `event_id` (UUID). The database model enforces a unique index on `event_id`. The ingestion service performs an upsert/skip on conflict, returning HTTP 200/201 with duplicate count metrics without throwing errors.
- **Consequence**: Guaranteed idempotency and zero duplicate records in analytics.

## ADR 004: Evidence-Based MITRE ATT&CK Mapping
- **Context**: Telemetry must be mapped to MITRE ATT&CK techniques, but assigning techniques without concrete evidence produces false threat intelligence.
- **Decision**: The MITRE engine only maps techniques when specific verifiable evidence exists in the event payload (e.g., failed login sequence $\to$ `T1110.001`, bait credential trigger $\to$ `T1078`, shell command input $\to$ `T1059.004`, file download $\to$ `T1048`). Each mapping records the triggering `event_id`, confidence rating, and evidence description.
- **Consequence**: Defensible, audit-ready threat intelligence.

## ADR 005: Strict Credential Sanitization
- **Context**: Honeytokens and bait accounts capture attacker login attempts. Storing raw plaintext passwords poses a security and compliance risk.
- **Decision**: The backend never stores or returns plaintext passwords in API responses or general logs. Only `password_length`, username, and bait-trigger flags are retained.
- **Consequence**: Robust defense against credential leakage in dashboard telemetry.

## ADR 006: Real-Time Telemetry Streaming via Native WebSockets with REST Fallback
- **Context**: The frontend dashboard (Person 3) requires live updates as attacks occur without aggressive interval polling.
- **Decision**: Provide native WebSocket streaming endpoint `/ws/events`. The backend maintains active connections via `WebSocketManager` and pushes `NEW_EVENT` JSON frames on ingestion. A lightweight text-based heartbeat (`ping` $\to$ `pong`) prevents intermediate proxy timeouts. Ingestion and REST endpoints execute synchronously/asynchronously without failing if no WebSocket clients are connected.
- **Consequence**: Zero-lag real-time dashboard updates with automatic fallback to REST polling (`GET /api/dashboard/stats`).

## ADR 007: Dual Pagination Contract (`page_size` and `limit` Aliasing)
- **Context**: Different frontend libraries, state managers, and data grids expect either `page_size` or `limit` query parameters and response attributes.
- **Decision**: REST query parameters accept both `page_size` and `limit`. Paginated responses (`PaginatedEventsResponse`, `PaginatedAttackersResponse`, `PaginatedSessionsResponse`) return both `page_size` and `limit` (synced via Pydantic model validators).
- **Consequence**: Seamless frontend DX; Person 3 can integrate standard data table components (TanStack Table, Material-UI, AG Grid) without custom parameter transformation.

## ADR 008: Dynamic Environment-Configurable CORS (`FRONTEND_ORIGINS`)
- **Context**: Person 3 will run React + Vite on `http://localhost:5173` or `http://localhost:3000` during development, but staging/production will host on external domains or IPs.
- **Decision**: `CORS_ORIGINS` in `backend/app/core/config.py` merges default local development origins with any comma-separated or JSON list provided in `FRONTEND_ORIGINS` or `CORS_ORIGINS` environment variables.
- **Consequence**: Person 3 can configure their frontend URL in `.env` without modifying backend source code.

## ADR 009: Ingestion Endpoint Aliasing
- **Context**: Decoys, forwarders, and integration test suites historical call `/api/events`, `/api/ingestion/events`, and `/api/ingest`.
- **Decision**: Route all three paths to the same unified `ingest_events` controller in `backend/app/api/routes/ingestion.py`.
- **Consequence**: Complete forward and backward compatibility across all modules and tests.

