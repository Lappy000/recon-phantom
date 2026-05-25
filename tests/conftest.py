"""Pytest fixtures and configuration for Recon Phantom tests."""

from __future__ import annotations

import asyncio
from typing import AsyncGenerator, Generator
from unittest.mock import AsyncMock, MagicMock

import pytest
import pytest_asyncio

from recon_phantom.config import Settings, override_settings
from recon_phantom.core.engine import ScanEngine
from recon_phantom.core.events import EventBus


@pytest.fixture(scope="session")
def event_loop() -> Generator[asyncio.AbstractEventLoop, None, None]:
    """Create an event loop for the test session."""
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
def settings() -> Settings:
    """Create test settings with SQLite in-memory database."""
    test_settings = Settings(
        debug=True,
        database_url="sqlite+aiosqlite:///:memory:",
        api_host="127.0.0.1",
        api_port=9999,
    )
    override_settings(test_settings)
    return test_settings


@pytest.fixture
def event_bus() -> EventBus:
    """Create a fresh event bus for testing."""
    return EventBus(max_queue_size=100)


@pytest_asyncio.fixture
async def engine(settings: Settings, event_bus: EventBus) -> AsyncGenerator[ScanEngine, None]:
    """Create and start a scan engine for testing."""
    eng = ScanEngine(settings=settings, event_bus=event_bus)
    await eng.start(num_workers=1)
    yield eng
    await eng.stop()


@pytest_asyncio.fixture
async def db_session(settings: Settings):
    """Initialize in-memory database and provide session."""
    from recon_phantom.core.database import close_database, get_session, init_database

    await init_database(settings.database_url)
    async with get_session() as session:
        yield session
    await close_database()


@pytest.fixture
def mock_http_response() -> MagicMock:
    """Create a mock HTTP response."""
    response = MagicMock()
    response.status_code = 200
    response.headers = {"Server": "nginx/1.24.0", "Content-Type": "text/html"}
    response.text = "<html><body>Test</body></html>"
    response.content = b"<html><body>Test</body></html>"
    return response


@pytest.fixture
def sample_findings() -> list[dict]:
    """Sample findings for testing reporters."""
    return [
        {
            "module": "port_scanner",
            "severity": "info",
            "title": "Open port 80/http",
            "description": "Port 80 is open running nginx 1.24.0",
            "host": "example.com",
            "port": 80,
            "protocol": "tcp",
            "evidence": "HTTP/1.1 200 OK\nServer: nginx/1.24.0",
        },
        {
            "module": "port_scanner",
            "severity": "medium",
            "title": "Open port 6379/redis",
            "description": "Redis server exposed without authentication",
            "host": "example.com",
            "port": 6379,
            "protocol": "tcp",
            "evidence": "+PONG",
        },
        {
            "module": "ssl_analyzer",
            "severity": "high",
            "title": "Expired SSL Certificate",
            "description": "SSL certificate expired 30 days ago",
            "host": "example.com",
            "port": 443,
            "protocol": "https",
            "evidence": "Not After: 2024-01-01",
        },
    ]
