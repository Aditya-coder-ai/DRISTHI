"""API tests for WebSocket real-time event streaming."""

import pytest


def test_websocket_connection_and_heartbeat(client):
    with client.websocket_connect("/ws/events") as websocket:
        websocket.send_text("ping")
        data = websocket.receive_text()
        assert data == "pong"

