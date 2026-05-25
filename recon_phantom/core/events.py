"""Event bus for real-time scan updates via pub/sub pattern."""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Coroutine, Optional
from uuid import UUID


class EventType(str, Enum):
    """Scan lifecycle events."""

    SCAN_CREATED = "scan.created"
    SCAN_STARTED = "scan.started"
    SCAN_PROGRESS = "scan.progress"
    SCAN_MODULE_STARTED = "scan.module.started"
    SCAN_MODULE_COMPLETED = "scan.module.completed"
    SCAN_MODULE_FAILED = "scan.module.failed"
    SCAN_COMPLETED = "scan.completed"
    SCAN_FAILED = "scan.failed"
    SCAN_CANCELLED = "scan.cancelled"

    FINDING_NEW = "finding.new"
    FINDING_CRITICAL = "finding.critical"

    TARGET_ADDED = "target.added"
    TARGET_RESOLVED = "target.resolved"

    ENGINE_OVERLOAD = "engine.overload"
    ENGINE_IDLE = "engine.idle"


@dataclass
class ScanEvent:
    """A single event emitted during scan lifecycle."""

    event_type: EventType
    scan_id: Optional[UUID] = None
    module_name: Optional[str] = None
    data: dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)
    severity: str = "info"

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dict for WebSocket/JSON transport."""
        return {
            "type": self.event_type.value,
            "scan_id": str(self.scan_id) if self.scan_id else None,
            "module": self.module_name,
            "data": self.data,
            "timestamp": self.timestamp,
            "severity": self.severity,
        }


# Type alias for event handler coroutines
EventHandler = Callable[[ScanEvent], Coroutine[Any, Any, None]]


class EventBus:
    """
    Async pub/sub event bus for distributing scan events to subscribers.
    
    Supports:
    - Topic-based subscription (subscribe to specific event types)
    - Wildcard subscription (receive all events)
    - Per-scan subscription (only events for a specific scan ID)
    - Queue-based delivery (subscribers get their own async queue)
    """

    def __init__(self, max_queue_size: int = 1000):
        self._handlers: dict[EventType, list[EventHandler]] = {}
        self._wildcard_handlers: list[EventHandler] = []
        self._scan_queues: dict[UUID, list[asyncio.Queue[ScanEvent]]] = {}
        self._global_queues: list[asyncio.Queue[ScanEvent]] = []
        self._max_queue_size = max_queue_size
        self._event_count = 0
        self._dropped_count = 0

    def subscribe(self, event_type: EventType, handler: EventHandler) -> None:
        """Subscribe a handler to a specific event type."""
        if event_type not in self._handlers:
            self._handlers[event_type] = []
        self._handlers[event_type].append(handler)

    def subscribe_all(self, handler: EventHandler) -> None:
        """Subscribe a handler to ALL events."""
        self._wildcard_handlers.append(handler)

    def unsubscribe(self, event_type: EventType, handler: EventHandler) -> None:
        """Remove a handler subscription."""
        if event_type in self._handlers:
            self._handlers[event_type] = [h for h in self._handlers[event_type] if h != handler]

    def create_queue(self, scan_id: Optional[UUID] = None) -> asyncio.Queue[ScanEvent]:
        """
        Create a queue that receives events.
        
        If scan_id is provided, only events for that scan are delivered.
        Otherwise, all events are delivered (useful for dashboard).
        """
        queue: asyncio.Queue[ScanEvent] = asyncio.Queue(maxsize=self._max_queue_size)

        if scan_id:
            if scan_id not in self._scan_queues:
                self._scan_queues[scan_id] = []
            self._scan_queues[scan_id].append(queue)
        else:
            self._global_queues.append(queue)

        return queue

    def remove_queue(self, queue: asyncio.Queue[ScanEvent], scan_id: Optional[UUID] = None) -> None:
        """Remove a queue from subscriptions."""
        if scan_id and scan_id in self._scan_queues:
            self._scan_queues[scan_id] = [q for q in self._scan_queues[scan_id] if q != queue]
            if not self._scan_queues[scan_id]:
                del self._scan_queues[scan_id]
        else:
            self._global_queues = [q for q in self._global_queues if q != queue]

    async def emit(self, event: ScanEvent) -> None:
        """
        Emit an event to all relevant subscribers.
        
        Delivery order:
        1. Specific event type handlers
        2. Wildcard handlers
        3. Scan-specific queues
        4. Global queues
        """
        self._event_count += 1

        # Invoke type-specific handlers
        handlers = self._handlers.get(event.event_type, [])
        for handler in handlers:
            try:
                await handler(event)
            except Exception:
                pass  # Don't let handler errors break the bus

        # Invoke wildcard handlers
        for handler in self._wildcard_handlers:
            try:
                await handler(event)
            except Exception:
                pass

        # Deliver to scan-specific queues
        if event.scan_id and event.scan_id in self._scan_queues:
            for queue in self._scan_queues[event.scan_id]:
                try:
                    queue.put_nowait(event)
                except asyncio.QueueFull:
                    self._dropped_count += 1

        # Deliver to global queues
        for queue in self._global_queues:
            try:
                queue.put_nowait(event)
            except asyncio.QueueFull:
                self._dropped_count += 1

    async def emit_progress(
        self,
        scan_id: UUID,
        module_name: str,
        current: int,
        total: int,
        message: str = "",
    ) -> None:
        """Convenience method for progress events."""
        await self.emit(ScanEvent(
            event_type=EventType.SCAN_PROGRESS,
            scan_id=scan_id,
            module_name=module_name,
            data={
                "current": current,
                "total": total,
                "percentage": round((current / total) * 100, 1) if total > 0 else 0,
                "message": message,
            },
        ))

    async def emit_finding(
        self,
        scan_id: UUID,
        module_name: str,
        finding: dict[str, Any],
        critical: bool = False,
    ) -> None:
        """Convenience method for new finding events."""
        event_type = EventType.FINDING_CRITICAL if critical else EventType.FINDING_NEW
        await self.emit(ScanEvent(
            event_type=event_type,
            scan_id=scan_id,
            module_name=module_name,
            data=finding,
            severity="critical" if critical else "info",
        ))

    @property
    def stats(self) -> dict[str, int]:
        """Get event bus statistics."""
        return {
            "total_events": self._event_count,
            "dropped_events": self._dropped_count,
            "active_scan_queues": sum(len(qs) for qs in self._scan_queues.values()),
            "active_global_queues": len(self._global_queues),
            "registered_handlers": sum(len(hs) for hs in self._handlers.values()) + len(self._wildcard_handlers),
        }


# Global event bus instance
_event_bus: Optional[EventBus] = None


def get_event_bus() -> EventBus:
    """Get or create the global event bus."""
    global _event_bus
    if _event_bus is None:
        _event_bus = EventBus()
    return _event_bus
