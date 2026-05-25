"""WebSocket endpoint for real-time scan progress updates."""

from __future__ import annotations

import asyncio
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from recon_phantom.core.events import EventBus, ScanEvent, get_event_bus

router = APIRouter()


class ConnectionManager:
    """Manages active WebSocket connections."""

    def __init__(self) -> None:
        self._active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket) -> None:
        """Accept and register a new WebSocket connection."""
        await websocket.accept()
        self._active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket) -> None:
        """Remove a disconnected WebSocket."""
        self._active_connections = [
            ws for ws in self._active_connections if ws != websocket
        ]

    async def broadcast(self, message: dict) -> None:
        """Broadcast a message to all connected clients."""
        disconnected = []
        for connection in self._active_connections:
            try:
                await connection.send_json(message)
            except Exception:
                disconnected.append(connection)
        for ws in disconnected:
            self.disconnect(ws)

    @property
    def active_count(self) -> int:
        return len(self._active_connections)


manager = ConnectionManager()


@router.websocket("/scans")
async def websocket_all_scans(websocket: WebSocket) -> None:
    """WebSocket endpoint for all scan events.

    Clients receive real-time updates for all active scans.
    """
    await manager.connect(websocket)
    event_bus = get_event_bus()
    queue = event_bus.create_queue()

    try:
        while True:
            # Listen for events from the bus
            try:
                event: ScanEvent = await asyncio.wait_for(queue.get(), timeout=30.0)
                await websocket.send_json(event.to_dict())
            except asyncio.TimeoutError:
                # Send heartbeat
                await websocket.send_json({"type": "heartbeat", "data": {}})
    except WebSocketDisconnect:
        pass
    except Exception:
        pass
    finally:
        manager.disconnect(websocket)
        event_bus.remove_queue(queue)


@router.websocket("/scans/{scan_id}")
async def websocket_scan_progress(websocket: WebSocket, scan_id: str) -> None:
    """WebSocket endpoint for a specific scan's events.

    Clients receive real-time updates only for the specified scan.
    """
    await manager.connect(websocket)
    event_bus = get_event_bus()

    try:
        scan_uuid = UUID(scan_id)
    except ValueError:
        await websocket.close(code=4000, reason="Invalid scan ID")
        return

    queue = event_bus.create_queue(scan_id=scan_uuid)

    try:
        while True:
            try:
                event: ScanEvent = await asyncio.wait_for(queue.get(), timeout=30.0)
                await websocket.send_json(event.to_dict())
            except asyncio.TimeoutError:
                await websocket.send_json({"type": "heartbeat", "scan_id": scan_id})
    except WebSocketDisconnect:
        pass
    except Exception:
        pass
    finally:
        manager.disconnect(websocket)
        event_bus.remove_queue(queue, scan_id=scan_uuid)
