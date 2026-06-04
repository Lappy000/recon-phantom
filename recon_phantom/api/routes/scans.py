"""Scan CRUD API endpoints."""

from __future__ import annotations

from typing import Optional
from uuid import UUID

import orjson
from fastapi import APIRouter, HTTPException, Query, Request
from sqlalchemy import func, select

from recon_phantom.api.schemas import (
    FindingResponse,
    ScanCreateRequest,
    ScanListResponse,
    ScanResponse,
)
from recon_phantom.core.database import get_session
from recon_phantom.core.models import Scan, ScanResult, ScanStatus

router = APIRouter()


@router.post("/", response_model=ScanResponse, status_code=201)
async def create_scan(request: Request, body: ScanCreateRequest) -> ScanResponse:
    """Create and submit a new scan.

    Enqueues the scan for execution by the engine.
    """
    engine = request.app.state.engine

    try:
        scan_id = await engine.submit_scan(
            target=body.target,
            target_type=body.target_type,
            modules=body.modules,
            config=body.config,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    # Fetch the created scan
    async with get_session() as session:
        result = await session.execute(
            select(Scan).where(Scan.id == str(scan_id))
        )
        scan = result.scalar_one_or_none()
        if scan is None:
            raise HTTPException(status_code=500, detail="Failed to create scan")

        return ScanResponse(
            id=scan.id,
            target_id=scan.target_id,
            status=scan.status,
            modules=orjson.loads(scan.modules),
            progress_percent=scan.progress_percent,
            current_module=scan.current_module,
            total_findings=scan.total_findings,
            critical_findings=scan.critical_findings,
            high_findings=scan.high_findings,
            started_at=scan.started_at,
            completed_at=scan.completed_at,
            duration_seconds=scan.duration_seconds,
            error_message=scan.error_message,
            created_at=scan.created_at,
        )


@router.get("/", response_model=ScanListResponse)
async def list_scans(
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(20, ge=1, le=100, description="Results per page"),
    status_filter: Optional[str] = Query(None, alias="status", description="Filter by status"),
) -> ScanListResponse:
    """List all scans with pagination and optional status filter."""
    async with get_session() as session:
        # Build query
        query = select(Scan).order_by(Scan.created_at.desc())

        if status_filter:
            try:
                status_enum = ScanStatus(status_filter)
                query = query.where(Scan.status == status_enum)
            except ValueError:
                raise HTTPException(status_code=400, detail=f"Invalid status: {status_filter}")

        # Get total count
        count_query = select(func.count()).select_from(Scan)
        if status_filter:
            count_query = count_query.where(Scan.status == ScanStatus(status_filter))
        total_result = await session.execute(count_query)
        total = total_result.scalar() or 0

        # Apply pagination
        query = query.offset((page - 1) * page_size).limit(page_size)
        result = await session.execute(query)
        scans = result.scalars().all()

        return ScanListResponse(
            scans=[
                ScanResponse(
                    id=s.id,
                    target_id=s.target_id,
                    status=s.status,
                    modules=orjson.loads(s.modules),
                    progress_percent=s.progress_percent,
                    current_module=s.current_module,
                    total_findings=s.total_findings,
                    critical_findings=s.critical_findings,
                    high_findings=s.high_findings,
                    started_at=s.started_at,
                    completed_at=s.completed_at,
                    duration_seconds=s.duration_seconds,
                    error_message=s.error_message,
                    created_at=s.created_at,
                )
                for s in scans
            ],
            total=total,
            page=page,
            page_size=page_size,
        )


@router.get("/{scan_id}", response_model=ScanResponse)
async def get_scan(scan_id: str) -> ScanResponse:
    """Get details of a specific scan."""
    async with get_session() as session:
        result = await session.execute(
            select(Scan).where(Scan.id == scan_id)
        )
        scan = result.scalar_one_or_none()
        if scan is None:
            raise HTTPException(status_code=404, detail="Scan not found")

        return ScanResponse(
            id=scan.id,
            target_id=scan.target_id,
            status=scan.status,
            modules=orjson.loads(scan.modules),
            progress_percent=scan.progress_percent,
            current_module=scan.current_module,
            total_findings=scan.total_findings,
            critical_findings=scan.critical_findings,
            high_findings=scan.high_findings,
            started_at=scan.started_at,
            completed_at=scan.completed_at,
            duration_seconds=scan.duration_seconds,
            error_message=scan.error_message,
            created_at=scan.created_at,
        )


@router.delete("/{scan_id}", status_code=204, response_model=None)
async def cancel_scan(request: Request, scan_id: str) -> None:
    """Cancel a running or queued scan."""
    engine = request.app.state.engine

    try:
        scan_uuid = UUID(scan_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid scan ID format")

    cancelled = await engine.cancel_scan(scan_uuid)
    if not cancelled:
        # Check if scan exists
        async with get_session() as session:
            result = await session.execute(
                select(Scan).where(Scan.id == scan_id)
            )
            scan = result.scalar_one_or_none()
            if scan is None:
                raise HTTPException(status_code=404, detail="Scan not found")
            if scan.status in (ScanStatus.COMPLETED, ScanStatus.FAILED, ScanStatus.CANCELLED):
                raise HTTPException(status_code=409, detail=f"Scan already {scan.status.value}")


@router.get("/{scan_id}/results", response_model=list[FindingResponse])
async def get_scan_results(
    scan_id: str,
    severity: Optional[str] = Query(None, description="Filter by severity"),
    module: Optional[str] = Query(None, description="Filter by module"),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
) -> list[FindingResponse]:
    """Get findings/results for a specific scan."""
    async with get_session() as session:
        query = select(ScanResult).where(ScanResult.scan_id == scan_id)

        if severity:
            query = query.where(ScanResult.severity == severity)
        if module:
            query = query.where(ScanResult.module_name == module)

        query = query.offset((page - 1) * page_size).limit(page_size)
        result = await session.execute(query)
        findings = result.scalars().all()

        if not findings:
            # Check if scan exists
            scan_result = await session.execute(
                select(Scan).where(Scan.id == scan_id)
            )
            if scan_result.scalar_one_or_none() is None:
                raise HTTPException(status_code=404, detail="Scan not found")

        return [
            FindingResponse(
                id=f.id,
                scan_id=f.scan_id,
                module_name=f.module_name,
                severity=f.severity,
                title=f.title,
                description=f.description,
                evidence=f.evidence,
                remediation=f.remediation,
                host=f.host,
                port=f.port,
                path=f.path,
                protocol=f.protocol,
                confidence=f.confidence,
                cve_ids=f.cve_ids,
                created_at=f.created_at,
            )
            for f in findings
        ]
