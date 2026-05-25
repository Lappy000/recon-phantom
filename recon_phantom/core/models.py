"""SQLAlchemy models for scan persistence."""

from __future__ import annotations

import enum
from datetime import datetime
from typing import Any, Optional
from uuid import UUID, uuid4

from sqlalchemy import (
    JSON,
    Boolean,
    Column,
    DateTime,
    Enum as SAEnum,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    func,
)
from sqlalchemy.ext.asyncio import AsyncAttrs
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(AsyncAttrs, DeclarativeBase):
    """Base model class."""
    pass


class ScanStatus(str, enum.Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class Severity(str, enum.Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Target(Base):
    """Scan target (domain, IP, CIDR)."""

    __tablename__ = "targets"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    value: Mapped[str] = mapped_column(String(512), nullable=False, index=True)
    target_type: Mapped[str] = mapped_column(String(20), nullable=False)  # domain, ip, cidr, url
    resolved_ips: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON list
    metadata_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now(), onupdate=func.now())

    # Relationships
    scans: Mapped[list["Scan"]] = relationship("Scan", back_populates="target", cascade="all, delete-orphan")

    def __repr__(self) -> str:
        return f"<Target {self.target_type}:{self.value}>"


class Scan(Base):
    """A single scan execution against a target."""

    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    target_id: Mapped[str] = mapped_column(String(36), ForeignKey("targets.id"), nullable=False)
    status: Mapped[ScanStatus] = mapped_column(SAEnum(ScanStatus), default=ScanStatus.PENDING)
    modules: Mapped[str] = mapped_column(Text, nullable=False)  # JSON list of module names
    config_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # Per-scan config overrides

    # Timing
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    duration_seconds: Mapped[Optional[float]] = mapped_column(Float, nullable=True)

    # Progress
    progress_percent: Mapped[float] = mapped_column(Float, default=0.0)
    current_module: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)

    # Results summary
    total_findings: Mapped[int] = mapped_column(Integer, default=0)
    critical_findings: Mapped[int] = mapped_column(Integer, default=0)
    high_findings: Mapped[int] = mapped_column(Integer, default=0)

    # Error info
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())

    # Relationships
    target: Mapped["Target"] = relationship("Target", back_populates="scans")
    results: Mapped[list["ScanResult"]] = relationship("ScanResult", back_populates="scan", cascade="all, delete-orphan")

    def __repr__(self) -> str:
        return f"<Scan {self.id[:8]} status={self.status.value}>"


class ScanResult(Base):
    """Individual finding from a scanner module."""

    __tablename__ = "scan_results"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    scan_id: Mapped[str] = mapped_column(String(36), ForeignKey("scans.id"), nullable=False)
    module_name: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    severity: Mapped[Severity] = mapped_column(SAEnum(Severity), default=Severity.INFO)

    # Finding details
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    evidence: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # Raw response/data
    remediation: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Structured data
    data_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # Module-specific JSON

    # References
    cve_ids: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # Comma-separated
    references: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON list of URLs

    # Location
    host: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    port: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    path: Mapped[Optional[str]] = mapped_column(String(1024), nullable=True)
    protocol: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)

    # Confidence
    confidence: Mapped[float] = mapped_column(Float, default=1.0)
    false_positive: Mapped[bool] = mapped_column(Boolean, default=False)

    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())

    # Relationships
    scan: Mapped["Scan"] = relationship("Scan", back_populates="results")

    def __repr__(self) -> str:
        return f"<ScanResult [{self.severity.value}] {self.title[:40]}>"


class ScanSchedule(Base):
    """Scheduled/recurring scan configuration."""

    __tablename__ = "scan_schedules"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    target_id: Mapped[str] = mapped_column(String(36), ForeignKey("targets.id"), nullable=False)
    modules: Mapped[str] = mapped_column(Text, nullable=False)
    cron_expression: Mapped[str] = mapped_column(String(64), nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    config_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    last_run_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    next_run_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
