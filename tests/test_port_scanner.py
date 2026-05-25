"""Unit tests for the PortScanner module."""

from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from recon_phantom.config import Settings
from recon_phantom.core.events import EventBus
from recon_phantom.scanners.port_scanner import (
    PORT_SERVICE_MAP,
    SERVICE_PATTERNS,
    TOP_PORTS,
    PortScanner,
)


@pytest.fixture
def port_scanner(settings: Settings, event_bus: EventBus) -> PortScanner:
    """Create a port scanner instance for testing."""
    return PortScanner(
        target="127.0.0.1",
        target_type="ip",
        config={"concurrency": 10, "timeout": 2.0},
        event_bus=event_bus,
        settings=settings,
    )


class TestPortScanner:
    """Tests for the PortScanner class."""

    def test_module_name(self, port_scanner: PortScanner):
        """Test module name property."""
        assert port_scanner.module_name == "port_scanner"

    def test_top_ports_length(self):
        """Test that TOP_PORTS has a substantial list."""
        assert len(TOP_PORTS) > 500
        assert 80 in TOP_PORTS
        assert 443 in TOP_PORTS
        assert 22 in TOP_PORTS

    def test_service_patterns_structure(self):
        """Test SERVICE_PATTERNS has expected services."""
        assert "ssh" in SERVICE_PATTERNS
        assert "http" in SERVICE_PATTERNS
        assert "ftp" in SERVICE_PATTERNS
        assert "mysql" in SERVICE_PATTERNS

    def test_port_service_map(self):
        """Test port-to-service mapping."""
        assert PORT_SERVICE_MAP[22] == "ssh"
        assert PORT_SERVICE_MAP[80] == "http"
        assert PORT_SERVICE_MAP[443] == "https"
        assert PORT_SERVICE_MAP[3306] == "mysql"
        assert PORT_SERVICE_MAP[5432] == "postgresql"

    def test_fingerprint_ssh_banner(self, port_scanner: PortScanner):
        """Test SSH banner fingerprinting."""
        service, version = port_scanner._fingerprint_service(
            "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4"
        )
        assert service == "OpenSSH"
        assert "8.9" in version

    def test_fingerprint_nginx_banner(self, port_scanner: PortScanner):
        """Test nginx banner fingerprinting."""
        service, version = port_scanner._fingerprint_service(
            "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0"
        )
        assert service == "nginx"
        assert version == "1.24.0"

    def test_fingerprint_apache_banner(self, port_scanner: PortScanner):
        """Test Apache banner fingerprinting."""
        service, version = port_scanner._fingerprint_service(
            "HTTP/1.1 200 OK\r\nServer: Apache/2.4.57 (Ubuntu)"
        )
        assert service == "Apache"
        assert version == "2.4.57"

    def test_fingerprint_redis_banner(self, port_scanner: PortScanner):
        """Test Redis banner fingerprinting."""
        service, version = port_scanner._fingerprint_service("+PONG")
        assert service == "Redis"

    def test_fingerprint_unknown_banner(self, port_scanner: PortScanner):
        """Test unknown banner returns empty."""
        service, version = port_scanner._fingerprint_service("some random data")
        assert service == ""
        assert version == ""

    def test_get_probes_http_port(self, port_scanner: PortScanner):
        """Test probe generation for HTTP ports."""
        probes = port_scanner._get_probes(80)
        assert len(probes) > 0
        assert any(b"GET / HTTP" in p for p in probes)

    def test_get_probes_redis_port(self, port_scanner: PortScanner):
        """Test probe generation for Redis port."""
        probes = port_scanner._get_probes(6379)
        assert any(b"PING" in p for p in probes)

    @pytest.mark.asyncio
    async def test_resolve_target_localhost(self, port_scanner: PortScanner):
        """Test resolving localhost."""
        result = await port_scanner.resolve_target()
        assert result == "127.0.0.1"

    @pytest.mark.asyncio
    async def test_scan_closed_port(self, port_scanner: PortScanner):
        """Test scanning a port that is likely closed."""
        semaphore = asyncio.Semaphore(10)
        # Port 1 is almost always closed
        result = await port_scanner.scan_port("127.0.0.1", 1, semaphore)
        # Should be None (closed/filtered)
        assert result is None

    def test_build_result_structure(self, port_scanner: PortScanner):
        """Test result dictionary structure."""
        result = port_scanner.build_result(
            title="Open port 80/http",
            description="Port 80 is open",
            severity="info",
            host="127.0.0.1",
            port=80,
            protocol="tcp",
        )
        assert result["title"] == "Open port 80/http"
        assert result["severity"] == "info"
        assert result["host"] == "127.0.0.1"
        assert result["port"] == 80
        assert result["module"] == "port_scanner"
        assert "scan_id" in result
        assert "timestamp" in result
