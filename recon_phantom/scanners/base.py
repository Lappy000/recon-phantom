"""Base scanner module providing abstract base class for all scanners.

All scanner implementations inherit from BaseScanner and implement the
async run() method to perform their specific reconnaissance tasks.
"""

import asyncio
import random
import time
import uuid
from abc import ABC, abstractmethod
from typing import Any, Optional

import httpx

from recon_phantom.config import Settings, get_settings
from recon_phantom.core.events import EventBus, get_event_bus


# Realistic User-Agent strings for stealth rotation
USER_AGENTS: list[str] = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.0.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
]


class BaseScanner(ABC):
    """Abstract base class for all reconnaissance scanners.

    Provides common infrastructure for HTTP requests with stealth capabilities,
    result building, event emission, and concurrency management.

    Attributes:
        target: The target host/domain/IP to scan.
        target_type: Type of target ('domain', 'ip', 'url', 'cidr').
        config: Scanner-specific configuration dictionary.
        event_bus: Event bus for publishing scan events.
        scan_id: Unique identifier for this scan session.
        settings: Application settings instance.
    """

    def __init__(
        self,
        target: str,
        target_type: str = "domain",
        config: Optional[dict[str, Any]] = None,
        event_bus: Optional[EventBus] = None,
        scan_id: Optional[uuid.UUID] = None,
        settings: Optional[Settings] = None,
    ) -> None:
        """Initialize the base scanner.

        Args:
            target: Target host/domain/IP/URL to scan.
            target_type: Type classification of the target.
            config: Scanner-specific configuration overrides.
            event_bus: Event bus instance for publishing events.
            scan_id: UUID for correlating scan results.
            settings: Application settings instance.
        """
        self.target = target
        self.target_type = target_type
        self.config = config or {}
        self.event_bus = event_bus or get_event_bus()
        self.scan_id = scan_id or uuid.uuid4()
        self.settings = settings or get_settings()
        self._http_client: Optional[httpx.AsyncClient] = None
        self._start_time: float = 0.0
        self._request_count: int = 0
        self._semaphore: Optional[asyncio.Semaphore] = None

    @property
    def module_name(self) -> str:
        """Return the scanner module name."""
        return self.__class__.__name__.lower().replace("scanner", "")

    @property
    def concurrency(self) -> int:
        """Return max concurrent operations from config."""
        return self.config.get("concurrency", 50)

    @property
    def timeout(self) -> float:
        """Return timeout in seconds from config."""
        return self.config.get("timeout", 10.0)

    @property
    def delay_range(self) -> tuple[float, float]:
        """Return min/max delay between requests for stealth."""
        min_delay = self.config.get("min_delay", 0.1)
        max_delay = self.config.get("max_delay", 0.5)
        return (min_delay, max_delay)

    def get_semaphore(self) -> asyncio.Semaphore:
        """Get or create the concurrency semaphore."""
        if self._semaphore is None:
            self._semaphore = asyncio.Semaphore(self.concurrency)
        return self._semaphore

    async def get_http_client(self) -> httpx.AsyncClient:
        """Get or create an HTTP client with stealth configuration.

        Returns:
            Configured httpx.AsyncClient instance.
        """
        if self._http_client is None or self._http_client.is_closed:
            self._http_client = httpx.AsyncClient(
                timeout=httpx.Timeout(self.timeout),
                follow_redirects=self.config.get("follow_redirects", True),
                verify=self.config.get("verify_ssl", False),
                limits=httpx.Limits(
                    max_connections=self.concurrency,
                    max_keepalive_connections=20,
                ),
            )
        return self._http_client

    def get_random_ua(self) -> str:
        """Return a random User-Agent string for request stealth."""
        return random.choice(USER_AGENTS)

    def get_stealth_headers(self) -> dict[str, str]:
        """Generate realistic HTTP headers for stealth requests.

        Returns:
            Dictionary of HTTP headers mimicking a real browser.
        """
        return {
            "User-Agent": self.get_random_ua(),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
            "Cache-Control": "max-age=0",
        }

    async def stealth_delay(self) -> None:
        """Apply a random delay between requests for stealth."""
        min_d, max_d = self.delay_range
        delay = random.uniform(min_d, max_d)
        await asyncio.sleep(delay)

    async def make_request(
        self,
        url: str,
        method: str = "GET",
        headers: Optional[dict[str, str]] = None,
        data: Optional[dict[str, Any]] = None,
        json_data: Optional[dict[str, Any]] = None,
        params: Optional[dict[str, str]] = None,
        follow_redirects: Optional[bool] = None,
        timeout: Optional[float] = None,
    ) -> Optional[httpx.Response]:
        """Make an HTTP request with stealth headers and error handling.

        Args:
            url: Target URL.
            method: HTTP method (GET, POST, etc.).
            headers: Additional headers (merged with stealth headers).
            data: Form data for POST requests.
            json_data: JSON body for POST requests.
            params: URL query parameters.
            follow_redirects: Override redirect behavior.
            timeout: Override request timeout.

        Returns:
            httpx.Response or None if the request failed.
        """
        client = await self.get_http_client()
        request_headers = self.get_stealth_headers()
        if headers:
            request_headers.update(headers)

        kwargs: dict[str, Any] = {
            "url": url,
            "headers": request_headers,
        }
        if params:
            kwargs["params"] = params
        if data:
            kwargs["data"] = data
        if json_data:
            kwargs["json"] = json_data
        if follow_redirects is not None:
            kwargs["follow_redirects"] = follow_redirects
        if timeout:
            kwargs["timeout"] = timeout

        try:
            await self.stealth_delay()
            self._request_count += 1
            response = await client.request(method, **kwargs)
            return response
        except httpx.TimeoutException:
            await self.emit_event("request_timeout", {"url": url})
            return None
        except httpx.ConnectError:
            await self.emit_event("connection_error", {"url": url})
            return None
        except httpx.HTTPError as e:
            await self.emit_event("http_error", {"url": url, "error": str(e)})
            return None

    def build_result(
        self,
        title: str,
        description: str,
        severity: str = "info",
        evidence: str = "",
        host: str = "",
        port: Optional[int] = None,
        path: str = "",
        protocol: str = "",
        data: Optional[dict[str, Any]] = None,
        confidence: float = 0.8,
        cve_ids: Optional[list[str]] = None,
    ) -> dict[str, Any]:
        """Build a standardized result dictionary.

        Args:
            title: Short title of the finding.
            description: Detailed description.
            severity: One of 'info', 'low', 'medium', 'high', 'critical'.
            evidence: Raw evidence supporting the finding.
            host: Target host for this finding.
            port: Port number if applicable.
            path: URL path if applicable.
            protocol: Protocol (tcp, http, https, etc.).
            data: Additional structured data.
            confidence: Confidence score 0.0 to 1.0.
            cve_ids: List of associated CVE identifiers.

        Returns:
            Standardized result dictionary.
        """
        return {
            "module": self.module_name,
            "severity": severity,
            "title": title,
            "description": description,
            "evidence": evidence,
            "host": host or self.target,
            "port": port,
            "path": path,
            "protocol": protocol,
            "data": data or {},
            "confidence": confidence,
            "cve_ids": cve_ids or [],
            "scan_id": str(self.scan_id),
            "timestamp": time.time(),
        }

    async def emit_event(self, event_type: str, data: Optional[dict[str, Any]] = None) -> None:
        """Emit an event through the event bus.

        Args:
            event_type: Type/name of the event.
            data: Event payload data.
        """
        event_data = {
            "scanner": self.module_name,
            "scan_id": str(self.scan_id),
            "target": self.target,
            **(data or {}),
        }
        await self.event_bus.emit(event_type, event_data)

    @abstractmethod
    async def run(self) -> list[dict[str, Any]]:
        """Execute the scanner and return results.

        Must be implemented by all scanner subclasses.

        Returns:
            List of result dictionaries from the scan.
        """
        ...

    async def __aenter__(self) -> "BaseScanner":
        """Async context manager entry."""
        self._start_time = time.time()
        await self.emit_event("scanner_started")
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Async context manager exit - cleanup resources."""
        if self._http_client and not self._http_client.is_closed:
            await self._http_client.aclose()
        elapsed = time.time() - self._start_time
        await self.emit_event(
            "scanner_completed",
            {"elapsed": elapsed, "requests": self._request_count},
        )

    async def execute(self) -> list[dict[str, Any]]:
        """Execute the scanner with proper lifecycle management.

        Returns:
            List of result dictionaries.
        """
        async with self:
            return await self.run()

    def get_base_url(self, scheme: str = "https") -> str:
        """Construct base URL from target.

        Args:
            scheme: URL scheme (http or https).

        Returns:
            Base URL string.
        """
        if self.target.startswith(("http://", "https://")):
            return self.target.rstrip("/")
        return f"{scheme}://{self.target}"
