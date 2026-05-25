"""Async database connection and session management."""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import AsyncGenerator

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from recon_phantom.config import get_settings
from recon_phantom.core.models import Base


_engine: AsyncEngine | None = None
_session_factory: async_sessionmaker[AsyncSession] | None = None


async def init_database(url: str | None = None) -> None:
    """Initialize the database engine and create tables."""
    global _engine, _session_factory

    if url is None:
        url = get_settings().database_url

    _engine = create_async_engine(
        url,
        echo=get_settings().debug,
        pool_pre_ping=True,
        pool_size=5,
        max_overflow=10,
    )

    _session_factory = async_sessionmaker(
        _engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )

    async with _engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def close_database() -> None:
    """Close the database engine."""
    global _engine, _session_factory
    if _engine:
        await _engine.dispose()
        _engine = None
        _session_factory = None


@asynccontextmanager
async def get_session() -> AsyncGenerator[AsyncSession, None]:
    """Get an async database session."""
    if _session_factory is None:
        await init_database()
    assert _session_factory is not None

    async with _session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


def get_engine() -> AsyncEngine:
    """Get the current engine (for raw queries)."""
    assert _engine is not None, "Database not initialized. Call init_database() first."
    return _engine
