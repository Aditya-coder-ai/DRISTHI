"""API tests for Attacker Profiles endpoints."""

def test_attackers_query_and_detail(client, sample_ssh_event):
    client.post("/api/events", json=sample_ssh_event)

    # 1. List attackers
    res = client.get("/api/attackers")
    assert res.status_code == 200
    data = res.json()
    assert data["total"] == 1
    attacker = data["items"][0]
    assert attacker["source_ip"] == sample_ssh_event["source_ip"]
    assert "ssh" in attacker["services_targeted"]
    assert "finance_admin" in attacker["attempted_usernames"]

    # 2. Get by attacker_id
    attacker_id = attacker["attacker_id"]
    res_det = client.get(f"/api/attackers/{attacker_id}")
    assert res_det.status_code == 200
    assert res_det.json()["attacker_id"] == attacker_id

    # 3. 404 on missing attacker
    res_404 = client.get("/api/attackers/non-existent-attacker")
    assert res_404.status_code == 404

