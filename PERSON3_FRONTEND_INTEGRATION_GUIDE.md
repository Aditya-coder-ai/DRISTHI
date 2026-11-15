# DRISTHI — Person 3 Frontend Integration Guide

> **Document Version:** 1.0  
> **Status:** FINAL — Backend is fully operational and ready for React + TypeScript integration  
> **Prepared by:** Person 2 — Central Backend & Database Engineer  
> **Target audience:** Person 3 — Frontend Engineer  

---

## Overview

The DRISTHI Central Backend is a **production-ready FastAPI application** that exposes:

- **11 REST API endpoints** — JSON over HTTP, fully documented
- **1 WebSocket endpoint** — real-time event streaming
- **Interactive Swagger UI** — live API explorer at `/docs`

The frontend must only **consume** these APIs. The backend handles all data storage, session management, event normalization, MITRE ATT&CK enrichment, and business logic.

---

## 1. Quick Start

### 1.1 Prerequisites

Ensure the backend is running before starting frontend development:

```bash
# From repo root D:\Drishti\DRISTHI
cd backend
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

Or via Docker Compose (if available):
```bash
docker compose up backend
```

### 1.2 Verify Backend is Running

```bash
curl http://localhost:8000/api/health
```

Expected:
```json
{"status": "healthy", "version": "1.0.0", "database": "connected", ...}
```

### 1.3 Enable CORS for Your Dev Server

Add to `backend/.env` (create this file from `backend/.env.example`):

```env
FRONTEND_ORIGINS=http://localhost:5173
```

> **Important:** Replace `5173` with whatever port your Vite/CRA dev server uses.  
> Multiple origins: `FRONTEND_ORIGINS=http://localhost:5173,http://localhost:3000`

Restart the backend after changing `.env`.

### 1.4 Explore the API Interactively

Open **http://localhost:8000/docs** in your browser — this is the live Swagger UI where you can test every endpoint before writing any frontend code.

---

## 2. Connection Details

| Setting            | Value                                     |
|-------------------|-------------------------------------------|
| REST Base URL      | `http://localhost:8000`                   |
| WebSocket URL      | `ws://localhost:8000/ws/events`           |
| Swagger UI         | `http://localhost:8000/docs`              |
| OpenAPI JSON       | `http://localhost:8000/openapi.json`      |
| Health check       | `GET http://localhost:8000/api/health`    |

---

## 3. All Endpoints at a Glance

| Method | Endpoint                     | Auth Required | Description                              |
|--------|------------------------------|---------------|------------------------------------------|
| GET    | `/api/health`                | No            | Backend health and DB status             |
| POST   | `/api/events`                | Yes (API Key) | Ingest honeypot events (Person 1 only)   |
| POST   | `/api/ingestion/events`      | Yes (API Key) | Alias for above                          |
| POST   | `/api/ingest`                | Yes (API Key) | Alias for above                          |
| GET    | `/api/events`                | No            | Paginated attack events (filterable)     |
| GET    | `/api/events/{id}`           | No            | Single event detail                      |
| GET    | `/api/attackers`             | No            | Paginated attacker profiles              |
| GET    | `/api/attackers/{id}`        | No            | Single attacker profile                  |
| GET    | `/api/sessions`              | No            | Paginated sessions                       |
| GET    | `/api/sessions/{id}`         | No            | Single session detail                    |
| GET    | `/api/dashboard/stats`       | No            | Dashboard summary statistics             |
| GET    | `/api/dashboard/timeline`    | No            | Attack timeline (time-bucketed)          |
| GET    | `/api/dashboard/services`    | No            | Per-service activity breakdown           |
| WS     | `ws://localhost:8000/ws/events` | No         | Real-time event stream                   |

> **Frontend only calls GET endpoints and the WebSocket.** The POST ingestion endpoints are reserved for the honeypot collector (Person 1) and must NOT be called from the UI.

---

## 4. Dashboard Component → Endpoint Mapping

Use this table to wire each dashboard widget to its data source:

| Dashboard Component           | Endpoint                                  | Response Field            |
|------------------------------|-------------------------------------------|---------------------------|
| Total attacks counter         | `GET /api/dashboard/stats`                | `.total_events`           |
| Unique attackers counter      | `GET /api/dashboard/stats`                | `.unique_attackers`       |
| Active sessions counter       | `GET /api/dashboard/stats`                | `.active_sessions`        |
| Canary triggers counter       | `GET /api/dashboard/stats`                | `.canary_triggers`        |
| Severity donut/pie chart      | `GET /api/dashboard/stats`                | `.severity_breakdown`     |
| Top usernames bar chart       | `GET /api/dashboard/stats`                | `.top_usernames[]`        |
| Top commands bar chart        | `GET /api/dashboard/stats`                | `.top_commands[]`         |
| Recent activity feed (static) | `GET /api/dashboard/stats`                | `.recent_events[]`        |
| Attack timeline chart         | `GET /api/dashboard/timeline?hours=24`    | `.buckets[]`              |
| Service breakdown table       | `GET /api/dashboard/services`             | `.services[]`             |
| Events data table             | `GET /api/events?page=1&limit=20`         | `.items[]`, `.total`      |
| Attackers data table          | `GET /api/attackers?page=1&limit=20`      | `.items[]`, `.total`      |
| Sessions data table           | `GET /api/sessions?page=1&limit=20`       | `.items[]`, `.total`      |
| Real-time event ticker        | `WS ws://localhost:8000/ws/events`        | frame `.data`             |

---

## 5. Response Shapes

### 5.1 Dashboard Stats (`GET /api/dashboard/stats`)

```typescript
interface DashboardStats {
  total_events: number;
  unique_attackers: number;
  active_sessions: number;
  canary_triggers: number;
  severity_breakdown: {
    low: number;
    medium: number;
    high: number;
    critical: number;
  };
  top_targeted_services: Array<{ service: string; count: number }>;
  top_usernames: Array<{ username: string; count: number }>;
  top_commands: Array<{ command: string; count: number }>;
  recent_events: AttackEvent[];  // Last 10 events, ordered newest first
}
```

### 5.2 Attack Event

```typescript
interface AttackEvent {
  event_id: string;
  session_id: string | null;
  source_ip: string;
  source_port: number | null;
  source_service: string;        // "ssh" | "ftp" | "web" | "database"
  asset_id: string;
  event_type: string;
  username: string | null;
  severity: "low" | "medium" | "high" | "critical";
  status: string;
  timestamp: string;             // ISO 8601
  activity: Record<string, unknown>;
  metadata: Record<string, unknown>;
  mitre_techniques: Array<{
    technique_id: string;        // e.g. "T1059.004"
    name: string;
    confidence: number;          // 0.0 – 1.0
  }>;
}
```

### 5.3 Paginated Response (Events / Attackers / Sessions)

```typescript
interface PaginatedResponse<T> {
  total: number;
  page: number;
  page_size: number;
  limit: number;         // Always equals page_size
  total_pages: number;
  items: T[];
}
```

### 5.4 Timeline (`GET /api/dashboard/timeline`)

```typescript
interface Timeline {
  interval: "hour" | "day";
  buckets: Array<{
    time_bucket: string;    // ISO 8601
    event_count: number;
    critical_count: number;
    high_count: number;
  }>;
}
```

### 5.5 Services (`GET /api/dashboard/services`)

```typescript
interface ServicesResponse {
  services: Array<{
    service: string;
    asset_id: string;
    total_events: number;
    unique_attackers: number;
    active_sessions: number;
    last_event_time: string | null;
  }>;
}
```

---

## 6. Pagination

All list endpoints (`/api/events`, `/api/attackers`, `/api/sessions`) support pagination.

### Request

```
GET /api/events?page=1&limit=20&service=ssh&severity=high
```

| Parameter   | Description                          | Default |
|------------|--------------------------------------|---------|
| `page`     | Page number (1-based)                | 1       |
| `limit`    | Items per page (max 200)             | 50      |
| `page_size`| Alias for `limit`                    | 50      |

> Use `limit` — it's cleaner. `page_size` exists for backward compatibility.

### Response pattern

```typescript
const response = await fetch('/api/events?page=1&limit=20');
const data: PaginatedResponse<AttackEvent> = await response.json();

// Render items
data.items.forEach(event => renderEventRow(event));

// Build pagination controls
const totalPages = data.total_pages;
const currentPage = data.page;
```

---

## 7. Real-Time WebSocket Integration

### 7.1 Connection

```typescript
const ws = new WebSocket('ws://localhost:8000/ws/events');

ws.onopen = () => {
  console.log('DRISTHI live feed connected');
};

ws.onmessage = (event) => {
  const frame = JSON.parse(event.data);
  if (frame.type === 'NEW_EVENT') {
    handleNewEvent(frame.data);
  }
};

ws.onclose = () => {
  console.log('WebSocket closed — reconnecting…');
  reconnectWithBackoff();
};
```

### 7.2 Frame Format

```typescript
interface WebSocketFrame {
  type: 'NEW_EVENT';
  data: {
    event_id: string;
    session_id: string;
    source_service: string;
    asset_id: string;
    source_ip: string;
    event_type: string;
    username: string | null;
    severity: string;
    timestamp: string;
  };
}
```

### 7.3 Heartbeat

Send `ping` every 30 seconds to keep the connection alive:

```typescript
setInterval(() => {
  if (ws.readyState === WebSocket.OPEN) {
    ws.send('ping');
  }
}, 30000);
```

The backend responds with `pong`.

### 7.4 Reconnect with Exponential Back-off

```typescript
let reconnectDelay = 1000; // ms

function reconnectWithBackoff() {
  setTimeout(() => {
    console.log(`Reconnecting in ${reconnectDelay}ms…`);
    connectWebSocket();
    reconnectDelay = Math.min(reconnectDelay * 2, 30000);
  }, reconnectDelay);
}

function connectWebSocket() {
  const ws = new WebSocket('ws://localhost:8000/ws/events');
  ws.onopen = () => { reconnectDelay = 1000; }; // reset on success
  ws.onclose = reconnectWithBackoff;
  // … attach onmessage etc.
}
```

---

## 8. Filtering Events

### Filter by service

```
GET /api/events?service=ssh
GET /api/events?service=ftp
GET /api/events?service=web
GET /api/events?service=database
```

### Filter by severity

```
GET /api/events?severity=critical
GET /api/events?severity=high
```

### Filter by time range

```
GET /api/events?start_time=2026-11-14T00:00:00Z&end_time=2026-11-14T23:59:59Z
```

### Sort order

```
GET /api/events?order_by=timestamp_desc   (newest first — default)
GET /api/events?order_by=timestamp_asc    (oldest first)
GET /api/events?order_by=severity_desc    (most severe first)
```

### Combined example (React `useEffect` pattern)

```typescript
const fetchEvents = async (page: number, service?: string, severity?: string) => {
  const params = new URLSearchParams({
    page: String(page),
    limit: '20',
    ...(service ? { service } : {}),
    ...(severity ? { severity } : {}),
    order_by: 'timestamp_desc',
  });
  const res = await fetch(`http://localhost:8000/api/events?${params}`);
  return res.json();
};
```

---

## 9. Error Handling

All errors return a consistent JSON body:

```typescript
interface ErrorResponse {
  error: string;
  details?: string | Record<string, unknown>;
}
```

| Status | Scenario                   |
|--------|----------------------------|
| 400    | Invalid query parameters   |
| 404    | Event / attacker / session not found |
| 422    | Schema validation failure  |
| 500    | Internal server error      |

```typescript
const res = await fetch('/api/events/nonexistent-id');
if (!res.ok) {
  const err = await res.json();
  console.error(err.error); // "Event not found"
}
```

---

## 10. Recommended Data Fetching Setup

### Axios base client (TypeScript)

```typescript
// src/api/client.ts
import axios from 'axios';

export const apiClient = axios.create({
  baseURL: import.meta.env.VITE_BACKEND_URL ?? 'http://localhost:8000',
  timeout: 10000,
  headers: { 'Content-Type': 'application/json' },
});
```

### Environment variable for backend URL

Create `frontend/.env.local`:
```env
VITE_BACKEND_URL=http://localhost:8000
```

### React Query example

```typescript
// src/hooks/useDashboardStats.ts
import { useQuery } from '@tanstack/react-query';
import { apiClient } from '../api/client';

export function useDashboardStats() {
  return useQuery({
    queryKey: ['dashboard', 'stats'],
    queryFn: () => apiClient.get('/api/dashboard/stats').then(r => r.data),
    refetchInterval: 30000, // Auto-refresh every 30s
  });
}
```

---

## 11. Important Constraints

| Constraint | Detail |
|-----------|--------|
| **Do NOT call ingestion endpoints** | `POST /api/events`, `POST /api/ingestion/events`, `POST /api/ingest` are for honeypot use only. Never call from the UI. |
| **Passwords are NEVER in responses** | Backend sanitizes all events. `password`, `passwd`, `secret`, `attempted_pass` fields are always redacted before storage. |
| **No sensitive data in URL params** | Never pass tokens or credentials in query strings. |
| **CORS must be configured** | Backend rejects requests from unlisted origins. Set `FRONTEND_ORIGINS` in backend `.env`. |
| **WebSocket is unauthenticated** | The event stream is a read-only push channel — no credentials needed. |
| **Timestamps are UTC ISO 8601** | All timestamps in the API are `Z`-suffixed UTC strings. Convert to local time in the UI. |

---

## 12. Integration Checklist for Person 3

Before starting frontend development, verify:

- [ ] Backend is running on port 8000: `curl http://localhost:8000/api/health` → `{"status": "healthy"}`
- [ ] `backend/.env` contains `FRONTEND_ORIGINS=http://localhost:<your-port>`
- [ ] Backend restarted after `.env` change
- [ ] Swagger UI accessible: http://localhost:8000/docs
- [ ] WebSocket connection test: open browser console, run `new WebSocket('ws://localhost:8000/ws/events')`

---

## 13. Contact & References

| Reference | Location |
|----------|----------|
| Full API Contract | `API_CONTRACT.md` |
| Database Schema | `DATABASE_SCHEMA.md` |
| Architecture Overview | `ARCHITECTURE.md` |
| Backend Readiness Report | `PERSON2_BACKEND_READINESS_REPORT.md` |
| Backend source | `backend/app/` |
| Backend tests (96 passing) | `backend/tests/` |
| Interactive API docs | http://localhost:8000/docs |

---

*DRISTHI — Adaptive Distributed Cyber Deception Platform Using Reinforcement Learning*  
*Person 2 Backend Handoff — November 2026*
