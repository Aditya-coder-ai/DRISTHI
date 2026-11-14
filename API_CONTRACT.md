# DRISTHI Central Backend — API Contract Specification

> **Revision:** 2.0 (Frontend Readiness Update — November 2026)
> **Status:** FINAL — Ready for Person 3 Frontend Integration

## Base URL
Default development: `http://localhost:8000`
Interactive Swagger UI: `http://localhost:8000/docs`
OpenAPI JSON schema: `http://localhost:8000/openapi.json`

---

## Authentication

### Ingestion Endpoints (Person 1 honeypot → Backend)
Endpoints: `POST /api/events`, `POST /api/ingestion/events`, `POST /api/ingest`
- Header: `X-API-Key: <token>` **OR** `Authorization: Bearer <token>`
- Token value: configured via `BACKEND_API_KEY` environment variable.
- If `BACKEND_API_KEY` is empty (development), authentication is bypassed.
- **Frontend (Person 3) does NOT call these endpoints.** They are honeypot ingestion-only.

### Public Read Endpoints (Frontend → Backend)
All `GET` endpoints (dashboard, events, attackers, sessions, health, timeline, services) are **open/unauthenticated** — no token required from the frontend.

### CORS
Configured via `FRONTEND_ORIGINS` environment variable (see Section 8).

---

## 1. System Health

### `GET /api/health`

**Response (200 OK):**
```json
{
  "status": "healthy",
  "version": "1.0.0",
  "database": "connected",
  "active_sessions": 3,
  "total_events": 1420,
  "timestamp": "2026-11-14T12:00:00Z"
}
```

---

## 2. Event Ingestion

### `POST /api/events`  ·  `POST /api/ingestion/events`  ·  `POST /api/ingest`

All three routes are **equivalent aliases** for honeypot event ingestion.  
Accepts a **single** `SecurityEvent` object **or** an **array** of `SecurityEvent` objects.

**Required Header:**
```
X-API-Key: <BACKEND_API_KEY value>
```

**Request Body (Person 1 SecurityEvent format):**
```json
[
  {
    "event_id": "c1f7b0a2-2c6e-4f0e-bdf1-30dbd4bfa101",
    "asset_id": "ssh-001",
    "event_type": "command_execution",
    "source_ip": "198.51.100.10",
    "source_port": 50220,
    "username": "finance_admin",
    "protocol": "SSH",
    "timestamp": "2026-11-14T01:00:00Z",
    "status": "executed",
    "metadata": {
      "command": "cat /etc/shadow",
      "session_id": "cowrie-sess-9821"
    }
  }
]
```

**Response (201 Created):**
```json
{
  "status": "success",
  "processed": 1,
  "persisted": 1,
  "duplicates_skipped": 0,
  "errors": []
}
```

---

## 3. Attack Events Query

### `GET /api/events`

**Query Parameters:**

| Parameter    | Type    | Default         | Description                                           |
|-------------|---------|-----------------|-------------------------------------------------------|
| `page`      | int     | 1               | Page number                                           |
| `page_size` | int     | 50 (max 200)    | Items per page                                        |
| `limit`     | int     | —               | Alias for `page_size` (frontend-friendly)             |
| `service`   | string  | —               | Filter by: `ssh`, `ftp`, `web`, `database`            |
| `severity`  | string  | —               | Filter by: `low`, `medium`, `high`, `critical`        |
| `event_type`| string  | —               | Filter by event type string                           |
| `source_ip` | string  | —               | Filter by attacker IP                                 |
| `start_time`| ISO8601 | —               | Filter events after this timestamp                    |
| `end_time`  | ISO8601 | —               | Filter events before this timestamp                   |
| `order_by`  | string  | `timestamp_desc`| Sort: `timestamp_asc`, `timestamp_desc`, `severity_desc` |

> **Frontend tip:** Use `limit` as a more intuitive alias for `page_size`.  
> Example: `GET /api/events?page=1&limit=20&service=ssh`

**Response (200 OK):**
```json
{
  "total": 120,
  "page": 1,
  "page_size": 20,
  "limit": 20,
  "total_pages": 6,
  "items": [
    {
      "event_id": "c1f7b0a2-2c6e-4f0e-bdf1-30dbd4bfa101",
      "session_id": "sess-uuid-4482",
      "source_ip": "198.51.100.10",
      "source_port": 50220,
      "source_service": "ssh",
      "asset_id": "ssh-001",
      "event_type": "command_execution",
      "username": "finance_admin",
      "severity": "high",
      "status": "executed",
      "timestamp": "2026-11-14T01:00:00Z",
      "activity": {
        "command": "cat /etc/shadow"
      },
      "metadata": {
        "session_id": "cowrie-sess-9821"
      },
      "mitre_techniques": [
        {
          "technique_id": "T1059.004",
          "name": "Unix Shell",
          "confidence": 0.95
        }
      ]
    }
  ]
}
```

> **Note:** `page_size` and `limit` are always equal in the response. Both are included for compatibility.

### `GET /api/events/{event_id}`

Returns complete event details.  
**Response:** Single `AttackEventResponse` object (same shape as `items[]` above).  
**404 Not Found** if event does not exist:
```json
{"error": "Event not found", "event_id": "<id>"}
```

---

## 4. Attacker Profiles

### `GET /api/attackers`

Aggregated attacker profiles by observed source IP.

**Query Parameters:**

| Parameter      | Type   | Default | Description                              |
|---------------|--------|---------|------------------------------------------|
| `page`        | int    | 1       | Page number                              |
| `page_size`   | int    | 20      | Items per page                           |
| `limit`       | int    | —       | Alias for `page_size`                    |
| `min_severity`| string | —       | Minimum severity filter                  |
| `search`      | string | —       | Search by IP or username substring       |

**Response (200 OK):**
```json
{
  "total": 5,
  "page": 1,
  "page_size": 20,
  "limit": 20,
  "total_pages": 1,
  "items": [
    {
      "attacker_id": "atk-198-51-100-10",
      "source_ip": "198.51.100.10",
      "total_events": 48,
      "total_sessions": 3,
      "first_seen": "2026-11-14T00:30:00Z",
      "last_seen": "2026-11-14T01:15:00Z",
      "services_targeted": ["ssh", "ftp", "web", "database"],
      "attempted_usernames": ["root", "finance_admin", "backup_user"],
      "attempted_commands": ["id", "uname -a", "cat /etc/passwd"],
      "highest_severity": "critical",
      "mitre_techniques": ["T1110.001", "T1078", "T1059.004"]
    }
  ]
}
```

### `GET /api/attackers/{attacker_id}`

Returns full attacker profile.  
**404 Not Found** if attacker does not exist.

---

## 5. Attacker Sessions

### `GET /api/sessions`

**Query Parameters:**

| Parameter   | Type   | Default | Description                                 |
|------------|--------|---------|---------------------------------------------|
| `status`   | string | —       | Filter: `active`, `idle`, `closed`          |
| `source_ip`| string | —       | Filter by attacker IP                       |
| `page`     | int    | 1       | Page number                                 |
| `page_size`| int    | 20      | Items per page                              |
| `limit`    | int    | —       | Alias for `page_size`                       |

**Response (200 OK):**
```json
{
  "total": 12,
  "page": 1,
  "page_size": 20,
  "limit": 20,
  "total_pages": 1,
  "items": [
    {
      "session_id": "sess-uuid-4482",
      "source_ip": "198.51.100.10",
      "source_service": "ssh",
      "asset_id": "ssh-001",
      "status": "active",
      "started_at": "2026-11-14T01:00:00Z",
      "last_activity": "2026-11-14T01:15:00Z",
      "ended_at": null,
      "event_count": 12,
      "severity_max": "high"
    }
  ]
}
```

### `GET /api/sessions/{session_id}`

Returns full session detail including associated events.  
**404 Not Found** if session does not exist.

---

## 6. Dashboard Analytics

### `GET /api/dashboard/stats`

100% computed from real database records. No hardcoded values.

**Response (200 OK):**
```json
{
  "total_events": 1420,
  "unique_attackers": 18,
  "active_sessions": 4,
  "canary_triggers": 6,
  "severity_breakdown": {
    "low": 600,
    "medium": 520,
    "high": 250,
    "critical": 50
  },
  "top_targeted_services": [
    {"service": "ssh", "count": 680},
    {"service": "web", "count": 420},
    {"service": "ftp", "count": 210},
    {"service": "database", "count": 110}
  ],
  "top_usernames": [
    {"username": "admin", "count": 190},
    {"username": "root", "count": 140},
    {"username": "finance_admin", "count": 85}
  ],
  "top_commands": [
    {"command": "uname -a", "count": 45},
    {"command": "whoami", "count": 38},
    {"command": "cat /etc/passwd", "count": 22}
  ],
  "recent_events": [
    {
      "event_id": "c1f7b0a2-2c6e-4f0e-bdf1-30dbd4bfa101",
      "session_id": "sess-uuid-4482",
      "source_ip": "198.51.100.10",
      "source_port": 50220,
      "source_service": "ssh",
      "asset_id": "ssh-001",
      "event_type": "command_execution",
      "username": "finance_admin",
      "severity": "high",
      "status": "executed",
      "timestamp": "2026-11-14T01:00:00Z",
      "activity": {"command": "cat /etc/shadow"},
      "metadata": {},
      "mitre_techniques": []
    }
  ]
}
```

> **`recent_events`** — The 10 most recent attack events ordered by `timestamp DESC`.  
> Same shape as `GET /api/events` items. Intended for the "Recent Activity" dashboard widget.

### `GET /api/dashboard/timeline`

**Query Parameters:**

| Parameter  | Type   | Default | Description                              |
|-----------|--------|---------|------------------------------------------|
| `interval`| string | `hour`  | Bucket size: `hour`, `day`               |
| `hours`   | int    | 24      | Lookback window in hours                 |
| `limit`   | int    | 24      | Max number of time buckets to return     |

**Response (200 OK):**
```json
{
  "interval": "hour",
  "buckets": [
    {
      "time_bucket": "2026-11-14T00:00:00Z",
      "event_count": 45,
      "critical_count": 3,
      "high_count": 12
    }
  ]
}
```

### `GET /api/dashboard/services`

Returns per-deception-asset operational activity.

**Response (200 OK):**
```json
{
  "services": [
    {
      "service": "ssh",
      "asset_id": "ssh-001",
      "total_events": 680,
      "unique_attackers": 10,
      "active_sessions": 2,
      "last_event_time": "2026-11-14T01:30:00Z"
    }
  ]
}
```

---

## 7. Real-Time WebSocket Streaming

### `WS /ws/events`

Connect to `ws://localhost:8000/ws/events` for real-time event push.

**Incoming frames (backend → frontend):**
```json
{
  "type": "NEW_EVENT",
  "data": {
    "event_id": "c1f7b0a2-2c6e-4f0e-bdf1-30dbd4bfa101",
    "session_id": "sess-uuid-4482",
    "source_service": "ssh",
    "asset_id": "ssh-001",
    "source_ip": "198.51.100.10",
    "event_type": "command_execution",
    "username": "finance_admin",
    "severity": "high",
    "timestamp": "2026-11-14T01:00:00Z"
  }
}
```

**Heartbeat (frontend → backend):**  
Send the string `ping` → backend responds `pong`.

**Connection lifecycle:**
- Reconnect on disconnect (exponential back-off recommended: 1s, 2s, 4s, 8s, max 30s).
- Backend removes disconnected clients silently.
- No authentication required for WebSocket (read-only stream).

---

## 8. CORS Configuration

CORS is controlled entirely via the `FRONTEND_ORIGINS` environment variable in `backend/.env`.

### Environment variable format

```env
# Single origin (Vite dev server):
FRONTEND_ORIGINS=http://localhost:5173

# Multiple origins (comma-separated):
FRONTEND_ORIGINS=http://localhost:5173,http://localhost:3000

# Production (replace or append):
FRONTEND_ORIGINS=https://dashboard.dristhi.internal
```

### What is allowed by default

```
http://localhost:3000
http://localhost:5173
http://localhost:8080
http://127.0.0.1:3000
http://127.0.0.1:5173
```

### CORS policy

| Setting                   | Value                                                |
|--------------------------|------------------------------------------------------|
| `allow_origins`          | Default list + all entries in `FRONTEND_ORIGINS`    |
| `allow_credentials`      | `true`                                               |
| `allow_methods`          | `["GET", "POST", "OPTIONS"]`                        |
| `allow_headers`          | `["*"]`                                              |

### Setup for Person 3

Add to `backend/.env`:
```env
FRONTEND_ORIGINS=http://localhost:5173
```
Restart the backend server. The React dev server origin is then whitelisted.

---

## 9. Error Responses

All error responses follow this structure:

```json
{
  "error": "Human-readable error message",
  "details": "Optional detail string or object"
}
```

| HTTP Status | Meaning                                         |
|------------|--------------------------------------------------|
| 400        | Bad request / validation failure                |
| 401        | Missing or invalid API key (ingestion routes)   |
| 404        | Resource not found                              |
| 409        | Duplicate event (already processed)             |
| 422        | Unprocessable entity (Pydantic validation)      |
| 500        | Internal server error                           |

---

## 10. Dashboard Component → Endpoint Mapping

| Dashboard Component          | Endpoint                              | Field / Key           |
|-----------------------------|---------------------------------------|-----------------------|
| Total attacks counter        | `GET /api/dashboard/stats`           | `total_events`        |
| Unique attackers counter     | `GET /api/dashboard/stats`           | `unique_attackers`    |
| Active sessions counter      | `GET /api/dashboard/stats`           | `active_sessions`     |
| Canary triggers counter      | `GET /api/dashboard/stats`           | `canary_triggers`     |
| Severity donut chart         | `GET /api/dashboard/stats`           | `severity_breakdown`  |
| Top usernames widget         | `GET /api/dashboard/stats`           | `top_usernames`       |
| Top commands widget          | `GET /api/dashboard/stats`           | `top_commands`        |
| Recent activity feed (static)| `GET /api/dashboard/stats`           | `recent_events`       |
| Attack timeline chart        | `GET /api/dashboard/timeline`        | `buckets`             |
| Service breakdown table      | `GET /api/dashboard/services`        | `services`            |
| Events data table            | `GET /api/events?page=1&limit=20`    | `items`, `total`      |
| Attackers data table         | `GET /api/attackers?page=1&limit=20` | `items`, `total`      |
| Sessions data table          | `GET /api/sessions?page=1&limit=20`  | `items`, `total`      |
| Real-time event ticker       | `WS ws://localhost:8000/ws/events`   | `data` (NEW_EVENT)    |

---

*Last updated: November 2026 — DRISTHI Person 2 Backend Team*
