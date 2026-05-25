"""Target management API endpoints."""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, HTTPException, Query
from sqlalchemy import func, select

from recon_phantom.api.schemas import TargetCreateRequest, TargetListResponse, TargetResponse
from recon_phantom.core.database import get_session
from recon_phantom.core.models import Scan, Target

router = APIRouter()


@router.post("/", response_model=TargetResponse, status_code=201)
async def create_target(body: TargetCreateRequest) -> TargetResponse:
    """Create a new target for scanning."""
    async with get_session() as session:
        target = Target(
            value=body.value,
            target_type=body.target_type,
            metadata_json=None,
        )
        session.add(target)
        await session.flush()
        await session.refresh(target)

        return TargetResponse(
            id=target.id,
            value=target.value,
            target_type=target.target_type,
            resolved_ips=target.resolved_ips,
            created_at=target.created_at,
            scan_count=0,
        )


@router.get("/", response_model=TargetListResponse)
async def list_targets(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    search: Optional[str] = Query(None, description="Search by target value"),
) -> TargetListResponse:
    """List all targets with pagination."""
    async with get_session() as session:
        query = select(Target).order_by(Target.created_at.desc())

        if search:
            query = query.where(Target.value.contains(search))

        # Count
        count_query = select(func.count()).select_from(Target)
        if search:
            count_query = count_query.where(Target.value.contains(search))
        total_result = await session.execute(count_query)
        total = total_result.scalar() or 0

        # Paginate
        query = query.offset((page - 1) * page_size).limit(page_size)
        result = await session.execute(query)
        targets = result.scalars().all()

        target_responses = []
        for t in targets:
            # Count scans for this target
            scan_count_result = await session.execute(
                select(func.count()).select_from(Scan).where(Scan.target_id == t.id)
            )
            scan_count = scan_count_result.scalar() or 0

            target_responses.append(TargetResponse(
                id=t.id,
                value=t.value,
                target_type=t.target_type,
                resolved_ips=t.resolved_ips,
                created_at=t.created_at,
                scan_count=scan_count,
            ))

        return TargetListResponse(targets=target_responses, total=total)


@router.get("/{target_id}", response_model=TargetResponse)
async def get_target(target_id: str) -> TargetResponse:
    """Get details of a specific target."""
    async with get_session() as session:
        result = await session.execute(
            select(Target).where(Target.id == target_id)
        )
        target = result.scalar_one_or_none()
        if target is None:
            raise HTTPException(status_code=404, detail="Target not found")

        scan_count_result = await session.execute(
            select(func.count()).select_from(Scan).where(Scan.target_id == target.id)
        )
        scan_count = scan_count_result.scalar() or 0

        return TargetResponse(
            id=target.id,
            value=target.value,
            target_type=target.target_type,
            resolved_ips=target.resolved_ips,
            created_at=target.created_at,
            scan_count=scan_count,
        )


@router.delete("/{target_id}", status_code=204)
async def delete_target(target_id: str) -> None:
    """Delete a target and all associated scans."""
    async with get_session() as session:
        result = await session.execute(
            select(Target).where(Target.id == target_id)
        )
        target = result.scalar_one_or_none()
        if target is None:
            raise HTTPException(status_code=404, detail="Target not found")

        await session.delete(target)
