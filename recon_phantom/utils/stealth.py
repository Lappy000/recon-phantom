"""Stealth utilities for evasive reconnaissance.

Provides user-agent rotation, request delay randomization, proxy rotation,
and fingerprint randomization to avoid detection by WAFs and IDS systems.
"""

from __future__ import annotations

import random
import time
from dataclasses import dataclass, field
from typing import Any, Optional


# 55 real-world User-Agent strings from various browsers and platforms
USER_AGENTS: list[str] = [
    # Chrome Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 11.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    # Chrome macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    # Chrome Linux
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
    # Firefox Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:119.0) Gecko/20100101 Firefox/119.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:118.0) Gecko/20100101 Firefox/118.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:115.0) Gecko/20100101 Firefox/115.0",
    # Firefox macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:120.0) Gecko/20100101 Firefox/120.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.2; rv:121.0) Gecko/20100101 Firefox/121.0",
    # Firefox Linux
    "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    # Safari macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    # Safari iOS
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPad; CPU OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
    # Edge
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36 Edg/118.0.0.0",
    # Opera
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 OPR/106.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 OPR/106.0.0.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 OPR/106.0.0.0",
    # Brave
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Brave/120",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Brave/120",
    # Android
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 13; SM-A546B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Mobile Safari/537.36",
    # Older but still common
    "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; CrOS x86_64 14541.0.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    # Vivaldi
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Vivaldi/6.5",
    # Arc browser
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Arc/1.20",
    # Samsung Internet
    "Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/23.0 Chrome/115.0.0.0 Mobile Safari/537.36",
    # UCBrowser
    "Mozilla/5.0 (Linux; U; Android 13; en-US; Redmi Note 12) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/100.0.4896.127 UCBrowser/16.1.0.1289 Mobile Safari/537.36",
    # Yandex
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 YaBrowser/24.1.0 Safari/537.36",
    # Curl/wget (for specific use cases)
    "curl/8.4.0",
    "Wget/1.21.4",
    # Googlebot (can sometimes bypass restrictions)
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X Build/MMB29P) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
]

# Accept header variations by browser type
ACCEPT_HEADERS: dict[str, str] = {
    "chrome": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
    "firefox": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "safari": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "edge": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
}

# Accept-Language variations
ACCEPT_LANGUAGES: list[str] = [
    "en-US,en;q=0.9",
    "en-US,en;q=0.9,es;q=0.8",
    "en-GB,en;q=0.9",
    "en-US,en;q=0.9,fr;q=0.8",
    "en-US,en;q=0.9,de;q=0.8",
    "en,en-US;q=0.9",
    "en-US,en;q=0.8",
    "en-US,en;q=0.9,ja;q=0.8",
    "en-US,en;q=0.5",
    "en-CA,en;q=0.9",
]


@dataclass
class ProxyConfig:
    """Configuration for a single proxy."""

    url: str
    protocol: str = "http"  # http, https, socks5
    username: Optional[str] = None
    password: Optional[str] = None
    failures: int = 0
    last_used: float = 0.0
    response_times: list[float] = field(default_factory=list)

    @property
    def avg_response_time(self) -> float:
        """Average response time in seconds."""
        if not self.response_times:
            return 0.0
        return sum(self.response_times[-10:]) / len(self.response_times[-10:])

    @property
    def proxy_url(self) -> str:
        """Full proxy URL with authentication."""
        if self.username and self.password:
            parsed_url = self.url.replace("://", f"://{self.username}:{self.password}@")
            return parsed_url
        return self.url


class UserAgentRotator:
    """Rotates user agents to avoid fingerprinting."""

    def __init__(self, agents: list[str] | None = None, sticky: bool = False):
        """Initialize the rotator.

        Args:
            agents: Custom list of user agents. Uses built-in list if None.
            sticky: If True, use the same UA for a session period.
        """
        self._agents = agents or USER_AGENTS
        self._sticky = sticky
        self._current: Optional[str] = None
        self._last_rotation: float = 0.0
        self._rotation_interval: float = 30.0  # seconds

    def get(self) -> str:
        """Get a user agent string.

        Returns:
            A user agent string, rotated based on settings.
        """
        if self._sticky:
            now = time.time()
            if self._current is None or (now - self._last_rotation) > self._rotation_interval:
                self._current = random.choice(self._agents)
                self._last_rotation = now
            return self._current
        return random.choice(self._agents)

    def get_browser_type(self, ua: str) -> str:
        """Determine browser type from UA string."""
        ua_lower = ua.lower()
        if "firefox" in ua_lower:
            return "firefox"
        elif "safari" in ua_lower and "chrome" not in ua_lower:
            return "safari"
        elif "edg" in ua_lower:
            return "edge"
        return "chrome"


class ProxyRotator:
    """Manages and rotates proxy connections."""

    def __init__(self, proxies: list[str] | None = None, max_failures: int = 5):
        """Initialize proxy rotator.

        Args:
            proxies: List of proxy URLs.
            max_failures: Max failures before removing a proxy.
        """
        self._proxies: list[ProxyConfig] = []
        self._max_failures = max_failures
        self._index = 0

        if proxies:
            for proxy_url in proxies:
                self._proxies.append(ProxyConfig(url=proxy_url))

    def add_proxy(self, url: str, username: str = "", password: str = "") -> None:
        """Add a proxy to the rotation pool."""
        self._proxies.append(
            ProxyConfig(url=url, username=username or None, password=password or None)
        )

    def get(self) -> Optional[str]:
        """Get next proxy URL from pool.

        Returns:
            Proxy URL string or None if no proxies available.
        """
        if not self._proxies:
            return None

        # Filter out failed proxies
        active = [p for p in self._proxies if p.failures < self._max_failures]
        if not active:
            return None

        # Round-robin selection
        proxy = active[self._index % len(active)]
        self._index += 1
        proxy.last_used = time.time()
        return proxy.proxy_url

    def report_failure(self, proxy_url: str) -> None:
        """Report a proxy failure."""
        for proxy in self._proxies:
            if proxy.url == proxy_url or proxy.proxy_url == proxy_url:
                proxy.failures += 1
                break

    def report_success(self, proxy_url: str, response_time: float) -> None:
        """Report successful proxy use with response time."""
        for proxy in self._proxies:
            if proxy.url == proxy_url or proxy.proxy_url == proxy_url:
                proxy.response_times.append(response_time)
                # Reduce failure count on success
                proxy.failures = max(0, proxy.failures - 1)
                break

    @property
    def active_count(self) -> int:
        """Number of active (non-failed) proxies."""
        return sum(1 for p in self._proxies if p.failures < self._max_failures)


def random_delay(min_seconds: float = 0.3, max_seconds: float = 1.5, jitter: float = 0.2) -> float:
    """Generate a random delay with optional jitter.

    Uses a triangular distribution biased toward the lower end for more
    natural-looking request timing.

    Args:
        min_seconds: Minimum delay.
        max_seconds: Maximum delay.
        jitter: Additional random jitter factor (0.0 to 1.0).

    Returns:
        Delay value in seconds.
    """
    # Triangular distribution biased toward min
    base_delay = random.triangular(min_seconds, max_seconds, min_seconds * 1.2)

    # Add jitter
    jitter_amount = base_delay * jitter * random.uniform(-1, 1)
    delay = max(min_seconds * 0.5, base_delay + jitter_amount)

    return delay


def randomize_headers(user_agent: str | None = None) -> dict[str, str]:
    """Generate a randomized set of HTTP headers mimicking a real browser.

    Args:
        user_agent: Specific UA to use. Random if None.

    Returns:
        Dictionary of HTTP headers.
    """
    rotator = UserAgentRotator()
    ua = user_agent or rotator.get()
    browser_type = rotator.get_browser_type(ua)

    headers: dict[str, str] = {
        "User-Agent": ua,
        "Accept": ACCEPT_HEADERS.get(browser_type, ACCEPT_HEADERS["chrome"]),
        "Accept-Language": random.choice(ACCEPT_LANGUAGES),
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
    }

    # Randomly add sec-fetch headers (modern browsers)
    if browser_type in ("chrome", "edge") and random.random() > 0.1:
        headers.update({
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": random.choice(["none", "same-origin", "cross-site"]),
            "Sec-Fetch-User": "?1",
            "Sec-Ch-Ua-Platform": random.choice(['"Windows"', '"macOS"', '"Linux"']),
        })

    # Randomly add cache control
    if random.random() > 0.5:
        headers["Cache-Control"] = random.choice(["max-age=0", "no-cache"])

    # Randomly add DNT
    if random.random() > 0.7:
        headers["DNT"] = "1"

    return headers


def generate_request_fingerprint() -> dict[str, Any]:
    """Generate a complete randomized request fingerprint.

    Returns:
        Dictionary with all fingerprint components for a request.
    """
    rotator = UserAgentRotator()
    ua = rotator.get()

    return {
        "headers": randomize_headers(ua),
        "delay": random_delay(),
        "tls_fingerprint": random.choice(["chrome", "firefox", "safari"]),
    }
