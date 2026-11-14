"""API tests for Attacker Sessions endpoints."""

def test_sessions_query_and_detail(client, sample_ssh_event):
    client.post("/api/events", json=sample_ssh_event)

    # 1. List sessions
    res = client.get("/api/sessions")
    assert res.status_code == 200
    data = res.json()
    assert data["total"] == 1
    session = data["items"][0]
    assert session["source_ip"] == sample_ssh_event["source_ip"]
    assert session["status"] == "active"

    # 2. Detail by session_id
    sess_id = session["session_id"]
    res_det = client.get(f"/api/sessions/{sess_id}")
    assert res_det.status_code == 200
    assert res_det.json()["session_id"] == sess_id

    # 3. 404 on missing session
    res_404 = client.get("/api/sessions/non-existent-session")
    assert res_404.status_code == 404

