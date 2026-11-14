"""API tests for Attack Events listing and filtering."""

def test_events_query_and_filtering(client, sample_ssh_event, sample_ftp_event, sample_canary_event):
    # Ingest 3 events
    client.post("/api/events", json=[sample_ssh_event, sample_ftp_event, sample_canary_event])

    # 1. List all events
    res = client.get("/api/events")
    assert res.status_code == 200
    data = res.json()
    assert data["total"] == 3
    assert len(data["items"]) == 3

    # 2. Filter by service = ssh
    res_ssh = client.get("/api/events?service=ssh")
    assert res_ssh.status_code == 200
    assert res_ssh.json()["total"] == 1
    assert res_ssh.json()["items"][0]["source_service"] == "ssh"

    # 3. Filter by severity = critical
    res_crit = client.get("/api/events?severity=critical")
    assert res_crit.status_code == 200
    assert res_crit.json()["total"] == 1
    assert res_crit.json()["items"][0]["event_type"] == "canary_triggered"

    # 4. Filter by source_ip
    res_ip = client.get("/api/events?source_ip=198.51.100.25")
    assert res_ip.status_code == 200
    assert res_ip.json()["total"] == 3

    # 5. Filter by username
    res_user = client.get("/api/events?username=finance_admin")
    assert res_user.status_code == 200
    assert res_user.json()["total"] == 1

    # 6. Pagination check
    res_page = client.get("/api/events?page=1&page_size=2")
    assert res_page.status_code == 200
    assert len(res_page.json()["items"]) == 2
    assert res_page.json()["total_pages"] == 2


def test_get_event_by_id(client, sample_ssh_event):
    client.post("/api/events", json=sample_ssh_event)

    # 1. Existing ID
    res = client.get(f"/api/events/{sample_ssh_event['event_id']}")
    assert res.status_code == 200
    assert res.json()["event_id"] == sample_ssh_event["event_id"]
    assert res.json()["source_service"] == "ssh"

    # 2. Non-existent ID
    res_404 = client.get("/api/events/non-existent-uuid")
    assert res_404.status_code == 404

