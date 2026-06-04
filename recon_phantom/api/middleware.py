"""API middleware for rate limiting and request logging."""

from __future__ import annotations

import time
from collections import defaultdict

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Simple IP-based rate limiting middleware.

    Tracks request counts per IP address within a sliding time window
    and returns 429 Too Many Requests when the limit is exceeded.
    """

    def __init__(
        self,
        app: object,
        max_requests: int = 100,
        window_seconds: int = 60,
    ) -> None:
        super().__init__(app)  # type: ignore[arg-type]
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._requests: dict[str, list[float]] = defaultdict(list)

    def _get_client_ip(self, request: Request) -> str:
        """Extract client IP from request, accounting for proxies."""
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            return forwarded.split(",")[0].strip()
        return request.client.host if request.client else "unknown"

    def _cleanup_old_requests(self, ip: str, now: float) -> None:
        """Remove expired request timestamps."""
        cutoff = now - self.window_seconds
        self._requests[ip] = [
            ts for ts in self._requests[ip] if ts > cutoff
        ]

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        """Process request with rate limit check."""
        # Skip rate limiting for health checks
        if request.url.path in ("/health", "/docs", "/redoc", "/openapi.json"):
            return await call_next(request)

        client_ip = self._get_client_ip(request)
        now = time.time()

        self._cleanup_old_requests(client_ip, now)

        if len(self._requests[client_ip]) >= self.max_requests:
            retry_after = int(self.window_seconds - (now - self._requests[client_ip][0]))
            return JSONResponse(
                status_code=429,
                content={
                    "detail": "Rate limit exceeded",
                    "type": "rate_limit_exceeded",
                    "retry_after": max(1, retry_after),
                },
                headers={"Retry-After": str(max(1, retry_after))},
            )

        self._requests[client_ip].append(now)
        return await call_next(request)


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """Request logging middleware with timing.

    Logs request method, path, status code, and duration for
    monitoring and debugging purposes.
    """

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        """Process request with timing and logging."""
        start_time = time.time()

        # Add request ID header
        request_id = f"{int(start_time * 1000)}"

        response = await call_next(request)

        # Calculate duration
        duration_ms = (time.time() - start_time) * 1000

        # Add timing headers
        response.headers["X-Request-ID"] = request_id
        response.headers["X-Response-Time"] = f"{duration_ms:.2f}ms"

        # Log slow requests (>1s) via structlog if available
        if duration_ms > 1000:
            import logging
            logger = logging.getLogger("recon_phantom.api")
            logger.warning(
                "Slow request: %s %s - %dms (status=%d)",
                request.method,
                request.url.path,
                int(duration_ms),
                response.status_code,
            )

        return response
