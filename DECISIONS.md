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

