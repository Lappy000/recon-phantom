"""FastAPI application factory with lifespan management, CORS, and error handling."""

from __future__ import annotations

import time
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from recon_phantom import __version__
from recon_phantom.config import get_settings


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifespan context manager.

    Handles startup and shutdown of database connections,
    scan engine, and background tasks.
    """
    from recon_phantom.core.database import close_database, init_database
    from recon_phantom.core.engine import ScanEngine
    from recon_phantom.core.events import get_event_bus

    settings = get_settings()

    # Startup
    await init_database(settings.database_url)

    # Create and start scan engine
    engine = ScanEngine(settings=settings)
    app.state.engine = engine
    app.state.event_bus = get_event_bus()
    await engine.start(num_workers=3)

    yield

    # Shutdown
    await engine.stop()
    await close_database()


def create_app() -> FastAPI:
    """Create and configure the FastAPI application.

    Returns:
        Configured FastAPI application instance.
    """
    settings = get_settings()

    app = FastAPI(
        title="Recon Phantom API",
        description="Async multi-engine reconnaissance & vulnerability scanner",
        version=__version__,
        lifespan=lifespan,
        docs_url="/docs",
        redoc_url="/redoc",
    )

    # CORS middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.api_cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Add custom middleware
    from recon_phantom.api.middleware import RateLimitMiddleware, RequestLoggingMiddleware
    app.add_middleware(RequestLoggingMiddleware)
    app.add_middleware(RateLimitMiddleware, max_requests=100, window_seconds=60)

    # Register routes
    from recon_phantom.api.routes.scans import router as scans_router
    from recon_phantom.api.routes.targets import router as targets_router
    from recon_phantom.api.routes.reports import router as reports_router
    from recon_phantom.api.routes.websocket import router as ws_router

    app.include_router(scans_router, prefix="/api/v1/scans", tags=["Scans"])
    app.include_router(targets_router, prefix="/api/v1/targets", tags=["Targets"])
    app.include_router(reports_router, prefix="/api/v1/reports", tags=["Reports"])
    app.include_router(ws_router, prefix="/ws", tags=["WebSocket"])

    # Exception handlers
    @app.exception_handler(ValueError)
    async def value_error_handler(request: Request, exc: ValueError) -> JSONResponse:
        return JSONResponse(
            status_code=400,
            content={"detail": str(exc), "type": "validation_error"},
        )

    @app.exception_handler(404)
    async def not_found_handler(request: Request, exc: Exception) -> JSONResponse:
        return JSONResponse(
            status_code=404,
            content={"detail": "Resource not found", "type": "not_found"},
        )

    @app.exception_handler(500)
    async def internal_error_handler(request: Request, exc: Exception) -> JSONResponse:
        return JSONResponse(
            status_code=500,
            content={"detail": "Internal server error", "type": "internal_error"},
        )

    # Health check endpoint
    @app.get("/health", tags=["System"])
    async def health_check() -> dict:
        """Health check endpoint."""
        return {
            "status": "healthy",
            "version": __version__,
            "timestamp": time.time(),
        }

    # Engine status endpoint
    @app.get("/api/v1/status", tags=["System"])
    async def system_status(request: Request) -> dict:
        """Get system and engine status."""
        engine = request.app.state.engine
        event_bus = request.app.state.event_bus
        return {
            "engine": {
                "active_scans": engine.active_scan_count,
                "queue_size": engine.queue_size,
                "registered_modules": engine.registered_modules,
            },
            "event_bus": event_bus.stats,
            "version": __version__,
        }

    return app
