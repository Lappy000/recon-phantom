"""Pydantic models for API request and response schemas."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field, field_validator


class ScanStatusEnum(str, Enum):
    """Scan status enumeration."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class SeverityEnum(str, Enum):
    """Finding severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


# --- Request Models ---


class ScanCreateRequest(BaseModel):
    """Request body for creating a new scan."""

    target: str = Field(..., min_length=1, max_length=512, description="Target to scan")
    target_type: str = Field(
        default="domain",
        description="Target type: domain, ip, cidr, url",
    )
    modules: Optional[list[str]] = Field(
        default=None,
        description="Scanner modules to run (null = all)",
    )
    config: Optional[dict[str, Any]] = Field(
        default=None,
        description="Per-scan configuration overrides",
    )

    @field_validator("target_type")
    @classmethod
    def validate_target_type(cls, v: str) -> str:
        valid = {"domain", "ip", "cidr", "url"}
        if v not in valid:
            raise ValueError(f"target_type must be one of: {valid}")
        return v


class TargetCreateRequest(BaseModel):
    """Request body for creating a new target."""

    value: str = Field(..., min_length=1, max_length=512, description="Target value")
    target_type: str = Field(default="domain", description="Target type")
    metadata: Optional[dict[str, Any]] = Field(default=None, description="Additional metadata")


class ReportRequest(BaseModel):
    """Request body for report generation."""

    scan_id: str = Field(..., description="Scan ID to generate report for")
    format: str = Field(default="html", description="Report format: html, json")
    include_evidence: bool = Field(default=True, description="Include raw evidence in report")


# --- Response Models ---


class ScanResponse(BaseModel):
    """Response model for scan data."""

    id: str
    target_id: str
    status: ScanStatusEnum
    modules: list[str]
    progress_percent: float
    current_module: Optional[str] = None
    total_findings: int
    critical_findings: int
    high_findings: int
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    duration_seconds: Optional[float] = None
    error_message: Optional[str] = None
    created_at: datetime

    class Config:
        from_attributes = True


class ScanListResponse(BaseModel):
    """Response model for scan listing."""

    scans: list[ScanResponse]
    total: int
    page: int
    page_size: int


class FindingResponse(BaseModel):
    """Response model for a single finding."""

    id: str
    scan_id: str
    module_name: str
    severity: SeverityEnum
    title: str
    description: Optional[str] = None
    evidence: Optional[str] = None
    remediation: Optional[str] = None
    host: Optional[str] = None
    port: Optional[int] = None
    path: Optional[str] = None
    protocol: Optional[str] = None
    confidence: float
    cve_ids: Optional[str] = None
    created_at: datetime

    class Config:
        from_attributes = True


class TargetResponse(BaseModel):
    """Response model for target data."""

    id: str
    value: str
    target_type: str
    resolved_ips: Optional[str] = None
    created_at: datetime
    scan_count: int = 0

    class Config:
        from_attributes = True


class TargetListResponse(BaseModel):
    """Response model for target listing."""

    targets: list[TargetResponse]
    total: int


class ErrorResponse(BaseModel):
    """Standard error response."""

    detail: str
    type: str = "error"
    code: Optional[str] = None


class ScanProgressEvent(BaseModel):
    """WebSocket event for scan progress updates."""

    event_type: str
    scan_id: Optional[str] = None
    module: Optional[str] = None
    data: dict[str, Any] = Field(default_factory=dict)
    timestamp: float
    severity: str = "info"
