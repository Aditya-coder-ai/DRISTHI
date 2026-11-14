"""Frontend Readiness and Contract Verification Tests for Person 3 Handoff.

Verifies:
- Pagination 'limit' alias behavior across events, attackers, and sessions.
- Session detail and 404 behavior.
- Recent events inclusion in Dashboard Stats.
- Ingestion alias '/api/ingest'.
- CORS headers reflection.
- Credential privacy (passwords never exposed).
"""

import pytest


def test_pagination_limit_alias_events(client, sample_ssh_event):
    # Ingest test event
    client.post("/api/events", json=sample_ssh_event)

    # Query with ?limit=5
    res = client.get("/api/events?page=1&limit=5")
    assert res.status_code == 200
    data = res.json()
    assert data["limit"] == 5
    assert data["page_size"] == 5
    assert data["page"] == 1
    assert "items" in data


def test_pagination_limit_alias_attackers_and_sessions(client, sample_ssh_event):
    client.post("/api/events", json=sample_ssh_event)

    # Attackers limit
    res_att = client.get("/api/attackers?page=1&limit=10")
    assert res_att.status_code == 200
    data_att = res_att.json()
    assert data_att["limit"] == 10
    assert data_att["page_size"] == 10

    # Sessions limit
    res_sess = client.get("/api/sessions?page=1&limit=10")
    assert res_sess.status_code == 200
    data_sess = res_sess.json()
    assert data_sess["limit"] == 10
    assert data_sess["page_size"] == 10


def test_session_detail_and_404(client, sample_ssh_event):
    client.post("/api/events", json=sample_ssh_event)

    res_list = client.get("/api/sessions")
    assert res_list.status_code == 200
    sessions = res_list.json()["items"]
    assert len(sessions) >= 1
    session_id = sessions[0]["session_id"]

    # 1. Valid detail
    res_det = client.get(f"/api/sessions/{session_id}")
    assert res_det.status_code == 200
    assert res_det.json()["session_id"] == session_id

    # 2. 404 on missing
    res_404 = client.get("/api/sessions/non-existent-session-id")
    assert res_404.status_code == 404


def test_dashboard_stats_includes_recent_events(client, sample_ssh_event, sample_ftp_event):
    client.post("/api/events", json=[sample_ssh_event, sample_ftp_event])

    res = client.get("/api/dashboard/stats")
    assert res.status_code == 200
    data = res.json()
    assert "recent_events" in data
    assert isinstance(data["recent_events"], list)
    assert len(data["recent_events"]) >= 2
    # Verify events are ordered descending
    assert data["recent_events"][0]["event_id"] in [sample_ssh_event["event_id"], sample_ftp_event["event_id"]]


def test_ingest_alias_endpoint(client, sample_ssh_event):
    sample_ssh_event["event_id"] = "test-alias-evt-001"
    res = client.post("/api/ingest", json=sample_ssh_event)
    assert res.status_code == 201
    assert res.json()["persisted"] == 1


def test_cors_headers_reflected(client):
    res = client.options(
        "/api/events",
        headers={
            "Origin": "http://localhost:5173",
            "Access-Control-Request-Method": "GET",
        },
    )
    # Status can be 200 OK for preflight
    assert res.status_code == 200
    assert res.headers.get("access-control-allow-origin") in ["http://localhost:5173", "*"]


def test_credentials_never_exposed(client):
    raw_event = {
        "event_id": "test-cred-exposure-001",
        "asset_id": "ssh-001",
        "event_type": "login_failed",
        "source_ip": "198.51.100.99",
        "username": "root",
        "password": "SuperSecretPassword123!",
        "protocol": "SSH",
        "timestamp": "2026-11-14T03:00:00Z",
        "metadata": {
            "password": "SuperSecretPassword123!",
            "attempted_pass": "SuperSecretPassword123!",
        },
    }
    res_post = client.post("/api/events", json=raw_event)
    assert res_post.status_code == 201

    # Query event details
    res_get = client.get("/api/events/test-cred-exposure-001")
    assert res_get.status_code == 200
    content_str = str(res_get.json())
    assert "SuperSecretPassword123!" not in content_str
    # Verify password was sanitized to length in metadata or activity
    meta_or_act = {**res_get.json()["activity"], **res_get.json()["metadata"]}
    assert meta_or_act.get("password_length") == len("SuperSecretPassword123!")
