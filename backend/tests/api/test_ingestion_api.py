"""API tests for event ingestion endpoints."""

from backend.app.core.config import settings


def test_ingest_single_event_success(client, sample_ssh_event):
    response = client.post("/api/events", json=sample_ssh_event)
    assert response.status_code == 201
    data = response.json()
    assert data["status"] == "success"
    assert data["processed"] == 1
    assert data["persisted"] == 1
    assert data["duplicates_skipped"] == 0


def test_ingest_batch_events_success(client, sample_ssh_event, sample_ftp_event, sample_canary_event):
    batch = [sample_ssh_event, sample_ftp_event, sample_canary_event]
    response = client.post("/api/events", json=batch)
    assert response.status_code == 201
    data = response.json()
    assert data["status"] == "success"
    assert data["processed"] == 3
    assert data["persisted"] == 3


def test_ingestion_endpoint_alias(client, sample_ftp_event):
    response = client.post("/api/ingestion/events", json=[sample_ftp_event])
    assert response.status_code == 201
    data = response.json()
    assert data["processed"] == 1
    assert data["persisted"] == 1


def test_ingest_duplicate_suppression(client, sample_ssh_event):
    # First post
    res1 = client.post("/api/events", json=sample_ssh_event)
    assert res1.status_code == 201
    assert res1.json()["persisted"] == 1

    # Second post of identical event_id
    res2 = client.post("/api/events", json=sample_ssh_event)
    assert res2.status_code == 201
    assert res2.json()["persisted"] == 0
    assert res2.json()["duplicates_skipped"] == 1


def test_ingest_api_key_authentication(client, sample_ssh_event, monkeypatch):
    monkeypatch.setattr(settings, "BACKEND_API_KEY", "secret-token-xyz")

    # 1. Missing auth header -> 401 Unauthorized
    res_unauth = client.post("/api/events", json=sample_ssh_event)
    assert res_unauth.status_code == 401

    # 2. Invalid auth header -> 401 Unauthorized
    res_wrong = client.post("/api/events", json=sample_ssh_event, headers={"X-API-Key": "wrong"})
    assert res_wrong.status_code == 401

    # 3. Valid X-API-Key header -> 201 Created
    sample_ssh_event["event_id"] = "auth-evt-1"
    res_valid = client.post("/api/events", json=sample_ssh_event, headers={"X-API-Key": "secret-token-xyz"})
    assert res_valid.status_code == 201

    # 4. Valid Authorization Bearer header -> 201 Created
    sample_ssh_event["event_id"] = "auth-evt-2"
    res_bearer = client.post("/api/events", json=sample_ssh_event, headers={"Authorization": "Bearer secret-token-xyz"})
    assert res_bearer.status_code == 201

