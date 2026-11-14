"""WebSocket Connection Manager for Real-Time Threat Telemetry Streaming."""

import asyncio
from typing import Any, Dict, List
from fastapi import WebSocket
from backend.app.core.logging import logger


class WebSocketManager:
    """Maintains active WebSocket connections and broadcasts sanitized event frames."""

    def __init__(self):
        self.active_connections: List[WebSocket] = []
        self._lock = asyncio.Lock()

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        async with self._lock:
            self.active_connections.append(websocket)
        logger.info("WebSocket client connected. Active connections: %d", len(self.active_connections))

    async def disconnect(self, websocket: WebSocket) -> None:
        async with self._lock:
            if websocket in self.active_connections:
                self.active_connections.remove(websocket)
        logger.info("WebSocket client disconnected. Active connections: %d", len(self.active_connections))

    async def broadcast(self, message: Dict[str, Any]) -> None:
        """Broadcasts JSON payload to all active clients, removing dead sockets."""
        async with self._lock:
            dead_connections = []
            for connection in self.active_connections:
                try:
                    await connection.send_json(message)
                except Exception as exc:
                    logger.debug("Failed to deliver message to WebSocket client: %s", exc)
                    dead_connections.append(connection)

            for dead in dead_connections:
                if dead in self.active_connections:
                    self.active_connections.remove(dead)

    def broadcast_sync(self, message: Dict[str, Any]) -> None:
        """Helper to schedule broadcast from synchronous request contexts."""
        if not self.active_connections:
            return
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                asyncio.run_coroutine_threadsafe(self.broadcast(message), loop)
            else:
                loop.run_until_complete(self.broadcast(message))
        except RuntimeError:
            # No running event loop in current thread
            pass


ws_manager = WebSocketManager()

