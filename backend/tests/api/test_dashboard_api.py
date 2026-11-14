"""API tests for Dashboard Analytics endpoints."""

def test_dashboard_stats_and_analytics(client, sample_ssh_event, sample_ftp_event, sample_canary_event):
    # Ingest 3 events
    client.post("/api/events", json=[sample_ssh_event, sample_ftp_event, sample_canary_event])

    # 1. /api/dashboard/stats
    res_stats = client.get("/api/dashboard/stats")
    assert res_stats.status_code == 200
    stats = res_stats.json()
    assert stats["total_events"] == 3
    assert stats["unique_attackers"] == 1
    assert stats["active_sessions"] >= 1
    assert stats["canary_triggers"] == 1
    assert stats["severity_breakdown"]["critical"] == 1
    assert len(stats["top_targeted_services"]) >= 2
    assert any(s["service"] == "ssh" for s in stats["top_targeted_services"])
    assert any(u["username"] == "finance_admin" for u in stats["top_usernames"])

    # 2. /api/dashboard/timeline
    res_timeline = client.get("/api/dashboard/timeline?hours=24")
    assert res_timeline.status_code == 200
    timeline = res_timeline.json()
    assert timeline["interval"] == "hour"
    assert len(timeline["buckets"]) >= 1

    # 3. /api/dashboard/services
    res_services = client.get("/api/dashboard/services")
    assert res_services.status_code == 200
    services = res_services.json()["services"]
    assert len(services) >= 2
    ssh_activity = next(s for s in services if s["service"] == "ssh")
    assert ssh_activity["total_events"] == 1

