"""Token bucket rate limiter with adaptive rate control.

Provides both fixed-rate and adaptive rate limiting that responds
to HTTP status codes (slowing down on 429 Too Many Requests).
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field


@dataclass
class RateLimiterStats:
    """Statistics for rate limiter monitoring."""

    total_requests: int = 0
    total_waits: int = 0
    total_wait_time: float = 0.0
    rate_reductions: int = 0
    current_rate: float = 0.0
    throttled_count: int = 0


class TokenBucketLimiter:
    """Token bucket rate limiter for controlling request rates.

    Tokens are added at a fixed rate. Each request consumes one token.
    If no tokens are available, the caller waits until one is replenished.

    Args:
        rate: Tokens added per second.
        burst: Maximum bucket capacity (burst allowance).
    """

    def __init__(self, rate: float = 10.0, burst: int = 20):
        self._rate = rate
        self._burst = burst
        self._tokens = float(burst)
        self._last_refill = time.monotonic()
        self._lock = asyncio.Lock()
        self._stats = RateLimiterStats(current_rate=rate)

    @property
    def rate(self) -> float:
        """Current token generation rate (tokens/second)."""
        return self._rate

    @rate.setter
    def rate(self, value: float) -> None:
        """Set the token generation rate."""
        self._rate = max(0.1, value)
        self._stats.current_rate = self._rate

    @property
    def available_tokens(self) -> float:
        """Currently available tokens (approximate)."""
        elapsed = time.monotonic() - self._last_refill
        return min(self._burst, self._tokens + elapsed * self._rate)

    @property
    def stats(self) -> RateLimiterStats:
        """Get rate limiter statistics."""
        return self._stats

    async def acquire(self, tokens: int = 1) -> float:
        """Acquire tokens, waiting if necessary.

        Args:
            tokens: Number of tokens to acquire.

        Returns:
            Time spent waiting in seconds.
        """
        async with self._lock:
            wait_time = 0.0

            # Refill tokens based on elapsed time
            now = time.monotonic()
            elapsed = now - self._last_refill
            self._tokens = min(self._burst, self._tokens + elapsed * self._rate)
            self._last_refill = now

            # Wait if insufficient tokens
            if self._tokens < tokens:
                deficit = tokens - self._tokens
                wait_time = deficit / self._rate
                self._stats.total_waits += 1
                self._stats.total_wait_time += wait_time

        if wait_time > 0:
            await asyncio.sleep(wait_time)
            async with self._lock:
                self._tokens = 0.0
                self._last_refill = time.monotonic()
        else:
            async with self._lock:
                self._tokens -= tokens

        self._stats.total_requests += 1
        return wait_time

    async def __aenter__(self) -> "TokenBucketLimiter":
        """Context manager entry - acquire one token."""
        await self.acquire()
        return self

    async def __aexit__(self, *args: object) -> None:
        """Context manager exit."""
        pass


class AdaptiveRateLimiter:
    """Rate limiter that adapts based on HTTP response status codes.

    Automatically reduces rate when receiving 429 (Too Many Requests)
    or 503 (Service Unavailable) responses, and gradually increases
    rate when requests succeed.

    Args:
        initial_rate: Starting requests per second.
        min_rate: Minimum rate floor.
        max_rate: Maximum rate ceiling.
        burst: Token bucket burst size.
        backoff_factor: Rate reduction factor on throttle (0-1).
        recovery_factor: Rate increase factor on success (>1).
        recovery_threshold: Consecutive successes before rate increase.
    """

    def __init__(
        self,
        initial_rate: float = 10.0,
        min_rate: float = 0.5,
        max_rate: float = 50.0,
        burst: int = 20,
        backoff_factor: float = 0.5,
        recovery_factor: float = 1.1,
        recovery_threshold: int = 10,
    ):
        self._min_rate = min_rate
        self._max_rate = max_rate
        self._backoff_factor = backoff_factor
        self._recovery_factor = recovery_factor
        self._recovery_threshold = recovery_threshold
        self._consecutive_successes = 0
        self._bucket = TokenBucketLimiter(rate=initial_rate, burst=burst)
        self._initial_rate = initial_rate

    @property
    def current_rate(self) -> float:
        """Current effective rate."""
        return self._bucket.rate

    @property
    def stats(self) -> RateLimiterStats:
        """Get combined statistics."""
        return self._bucket.stats

    async def acquire(self) -> float:
        """Acquire a token for making a request.

        Returns:
            Time spent waiting.
        """
        return await self._bucket.acquire()

    def report_response(self, status_code: int) -> None:
        """Report an HTTP response status code for rate adaptation.

        Args:
            status_code: HTTP status code from the response.
        """
        if status_code == 429 or status_code == 503:
            # Throttled - reduce rate
            new_rate = self._bucket.rate * self._backoff_factor
            self._bucket.rate = max(self._min_rate, new_rate)
            self._consecutive_successes = 0
            self._bucket.stats.rate_reductions += 1
            self._bucket.stats.throttled_count += 1
        elif status_code == 403:
            # Possible WAF detection - moderate reduction
            new_rate = self._bucket.rate * 0.7
            self._bucket.rate = max(self._min_rate, new_rate)
            self._consecutive_successes = 0
        elif 200 <= status_code < 400:
            # Success - potentially increase rate
            self._consecutive_successes += 1
            if self._consecutive_successes >= self._recovery_threshold:
                new_rate = self._bucket.rate * self._recovery_factor
                self._bucket.rate = min(self._max_rate, new_rate)
                self._consecutive_successes = 0

    def reset(self) -> None:
        """Reset rate to initial value."""
        self._bucket.rate = self._initial_rate
        self._consecutive_successes = 0

    async def __aenter__(self) -> "AdaptiveRateLimiter":
        """Context manager entry - acquire one token."""
        await self.acquire()
        return self

    async def __aexit__(self, *args: object) -> None:
        """Context manager exit."""
        pass
