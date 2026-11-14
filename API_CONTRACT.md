# DRISTHI Central Backend — API Contract Specification

## Base URL
Default: `http://localhost:8000`

## Authentication
- Ingestion endpoints (`POST /api/events`, `POST /api/ingestion/events`):
  - Header: `X-API-Key: <token>` OR `Authorization: Bearer <token>`
  - Configurable via `BACKEND_API_KEY` (if empty in development, open for testing).
- Public / Read endpoints (Dashboard, Events, Health):
  - Open or read-only access with optional CORS configuration.

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
### `POST /api/events` and `POST /api/ingestion/events`
Accepts a single `SecurityEvent` object or an array of `SecurityEvent` objects (Person 1 format or normalized schema).

**Request Body Example (Array of Person 1 SecurityEvents):**
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

**Response (201 Created or 200 OK):**
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
Query Parameters:
- `page` (int, default 1)
- `page_size` (int, default 50, max 200)
- `service` (string, optional: `ssh`, `ftp`, `web`, `database`)
- `severity` (string, optional: `low`, `medium`, `high`, `critical`)
- `event_type` (string, optional)
- `source_ip` (string, optional)
- `start_time` (ISO 8601 string, optional)
- `end_time` (ISO 8601 string, optional)
- `order_by` (string, default `timestamp_desc`, options: `timestamp_asc`, `timestamp_desc`, `severity_desc`)

**Response (200 OK):**
```json
{
  "total": 120,
  "page": 1,
  "page_size": 50,
  "total_pages": 3,
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

### `GET /api/events/{id}`
Returns complete event details or 404 Not Found.

---

## 4. Attacker Profiles
### `GET /api/attackers`
Returns aggregated attacker profiles by observed source IP.
Query Parameters: `page`, `page_size`, `min_severity`, `search` (IP or username).

**Response (200 OK):**
```json
{
  "total": 5,
  "page": 1,
  "page_size": 20,
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
      "attempted_commands": ["id", "uname -a", "cat /etc/shadow"],
      "highest_severity": "critical",
      "mitre_techniques": ["T1110.001", "T1078", "T1059.004"]
    }
  ]
}
```

---

## 5. Attacker Sessions
### `GET /api/sessions`
Query Parameters: `status` (`active`, `idle`, `closed`), `source_ip`, `page`, `page_size`.

### `GET /api/sessions/{id}`
Returns session telemetry timeline and associated attack events.

---

## 6. Dashboard Analytics
### `GET /api/dashboard/stats`
100% computed from real database records.
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
  ]
}
```

### `GET /api/dashboard/timeline`
Query Parameters: `interval` (e.g., `hour`, `day`), `limit` (default 24).
Returns time-bucketed event counts.

### `GET /api/dashboard/services`
Returns detailed operational activity per deception asset.

---

## 7. Real-Time WebSocket Streaming
### `WS /ws/events`
Clients receive real-time JSON frames upon event persistence:
```json
{
  "type": "NEW_EVENT",
  "data": {
    "event_id": "c1f7b0a2-2c6e-4f0e-bdf1-30dbd4bfa101",
    "source_service": "ssh",
    "source_ip": "198.51.100.10",
    "event_type": "command_execution",
    "severity": "high",
    "timestamp": "2026-11-14T01:00:00Z"
  }
}
```
Client ping/pong heartbeat supported. Disconnections handled gracefully.

