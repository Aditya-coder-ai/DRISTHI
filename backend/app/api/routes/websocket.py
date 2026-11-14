"""WebSocket router for live event streaming."""

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from backend.app.core.logging import logger
from backend.app.websocket.manager import ws_manager

router = APIRouter()


@router.websocket("/ws/events")
async def websocket_events_endpoint(websocket: WebSocket):
    """Establishes real-time push telemetry feed for the frontend dashboard."""
    await ws_manager.connect(websocket)
    try:
        while True:
            # Keep connection open, handle client heartbeats
            data = await websocket.receive_text()
            if data.strip().lower() == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        await ws_manager.disconnect(websocket)
    except Exception as exc:
        logger.debug("WebSocket client exception: %s", exc)
        await ws_manager.disconnect(websocket)

