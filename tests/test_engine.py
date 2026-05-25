"""Unit tests for the ScanEngine."""

from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import AsyncMock, patch
from uuid import UUID

import pytest
import pytest_asyncio

from recon_phantom.config import Settings
from recon_phantom.core.engine import ScanEngine, ScanTask
from recon_phantom.core.events import EventBus, EventType, ScanEvent
from recon_phantom.scanners.base import BaseScanner


class MockScanner(BaseScanner):
    """Mock scanner for testing."""

    @property
    def module_name(self) -> str:
        return "mock_scanner"

    async def run(self) -> list[dict[str, Any]]:
        """Return fake results."""
        await asyncio.sleep(0.1)
        return [
            self.build_result(
                title="Mock Finding",
                description="This is a mock finding for testing",
                severity="info",
                host=self.target,
                port=80,
            )
        ]


class FailingScanner(BaseScanner):
    """Scanner that always raises an error."""

    @property
    def module_name(self) -> str:
        return "failing_scanner"

    async def run(self) -> list[dict[str, Any]]:
        raise RuntimeError("Scanner failed intentionally")


class SlowScanner(BaseScanner):
    """Scanner that takes a long time."""

    @property
    def module_name(self) -> str:
        return "slow_scanner"

    async def run(self) -> list[dict[str, Any]]:
        await asyncio.sleep(100)  # Will be cancelled by timeout
        return []


class TestScanTask:
    """Tests for ScanTask dataclass."""

    def test_create_task(self):
        """Test creating a scan task."""
        task = ScanTask(
            scan_id=UUID("12345678-1234-1234-1234-123456789012"),
            target="example.com",
            target_type="domain",
            modules=["port_scanner"],
        )
        assert task.target == "example.com"
        assert task.target_type == "domain"
        assert not task.cancelled

    def test_cancel_task(self):
        """Test cancelling a task."""
        task = ScanTask(
            scan_id=UUID("12345678-1234-1234-1234-123456789012"),
            target="example.com",
            target_type="domain",
            modules=["port_scanner"],
        )
        task.cancel()
        assert task.cancelled


class TestScanEngine:
    """Tests for the ScanEngine class."""

    def test_register_scanner(self, settings: Settings, event_bus: EventBus):
        """Test registering a scanner module."""
        engine = ScanEngine(settings=settings, event_bus=event_bus)
        engine.register_scanner("mock", MockScanner)
        assert "mock" in engine.registered_modules

    def test_registered_modules(self, settings: Settings, event_bus: EventBus):
        """Test listing registered modules."""
        engine = ScanEngine(settings=settings, event_bus=event_bus)
        engine.register_scanner("scanner_a", MockScanner)
        engine.register_scanner("scanner_b", MockScanner)
        assert len(engine.registered_modules) == 2
        assert "scanner_a" in engine.registered_modules
        assert "scanner_b" in engine.registered_modules

    @pytest.mark.asyncio
    async def test_start_stop(self, settings: Settings, event_bus: EventBus):
        """Test starting and stopping the engine."""
        engine = ScanEngine(settings=settings, event_bus=event_bus)
        await engine.start(num_workers=2)
        assert engine._running is True
        assert len(engine._workers) == 2
        await engine.stop()
        assert engine._running is False

    @pytest.mark.asyncio
    async def test_submit_scan_invalid_module(self, settings: Settings, event_bus: EventBus):
        """Test submitting a scan with invalid modules."""
        engine = ScanEngine(settings=settings, event_bus=event_bus)
        engine.register_scanner("mock", MockScanner)
        await engine.start(num_workers=1)

        with pytest.raises(ValueError, match="Unknown scanner modules"):
            await engine.submit_scan(
                target="example.com",
                modules=["nonexistent_module"],
            )

        await engine.stop()

    @pytest.mark.asyncio
    async def test_active_scan_count(self, settings: Settings, event_bus: EventBus):
        """Test active scan counting."""
        engine = ScanEngine(settings=settings, event_bus=event_bus)
        assert engine.active_scan_count == 0
        assert engine.queue_size == 0

    @pytest.mark.asyncio
    async def test_event_emission_on_start(self, settings: Settings):
        """Test that engine emits events on start."""
        event_bus = EventBus()
        events_received: list[ScanEvent] = []

        async def handler(event: ScanEvent):
            events_received.append(event)

        event_bus.subscribe(EventType.ENGINE_IDLE, handler)

        engine = ScanEngine(settings=settings, event_bus=event_bus)
        await engine.start(num_workers=1)
        await asyncio.sleep(0.1)

        assert len(events_received) == 1
        assert events_received[0].event_type == EventType.ENGINE_IDLE

        await engine.stop()
