"""Report download API endpoints."""

from __future__ import annotations


from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import HTMLResponse, JSONResponse
from sqlalchemy import select

from recon_phantom.core.database import get_session
from recon_phantom.core.models import Scan, ScanResult

router = APIRouter()


@router.get("/{scan_id}", response_model=None)
async def generate_report(
    scan_id: str,
    format: str = Query("json", description="Report format: json, html"),
) -> JSONResponse | HTMLResponse:
    """Generate and download a report for a completed scan."""
    async with get_session() as session:
        # Verify scan exists
        scan_result = await session.execute(
            select(Scan).where(Scan.id == scan_id)
        )
        scan = scan_result.scalar_one_or_none()
        if scan is None:
            raise HTTPException(status_code=404, detail="Scan not found")

        # Fetch all results
        results_query = select(ScanResult).where(ScanResult.scan_id == scan_id)
        result = await session.execute(results_query)
        findings = result.scalars().all()

    # Build report data
    report_data = [
        {
            "id": f.id,
            "module": f.module_name,
            "severity": f.severity.value,
            "title": f.title,
            "description": f.description,
            "evidence": f.evidence,
            "host": f.host,
            "port": f.port,
            "path": f.path,
            "protocol": f.protocol,
            "confidence": f.confidence,
            "cve_ids": f.cve_ids,
            "created_at": f.created_at.isoformat() if f.created_at else None,
        }
        for f in findings
    ]

    if format == "html":
        from recon_phantom.reporters.html_reporter import HtmlReporter
        reporter = HtmlReporter()
        html_content = reporter.generate(report_data, scan_id=scan_id)
        return HTMLResponse(content=html_content)

    # Default: JSON
    return JSONResponse(
        content={
            "scan_id": scan_id,
            "status": scan.status.value,
            "total_findings": len(report_data),
            "findings": report_data,
        },
        headers={"Content-Disposition": f'attachment; filename="report-{scan_id[:8]}.json"'},
    )


@router.get("/{scan_id}/summary")
async def report_summary(scan_id: str) -> dict:
    """Get a summary of findings for a scan."""
    async with get_session() as session:
        scan_result = await session.execute(
            select(Scan).where(Scan.id == scan_id)
        )
        scan = scan_result.scalar_one_or_none()
        if scan is None:
            raise HTTPException(status_code=404, detail="Scan not found")

        results_query = select(ScanResult).where(ScanResult.scan_id == scan_id)
        result = await session.execute(results_query)
        findings = result.scalars().all()

    # Aggregate by severity
    severity_counts: dict[str, int] = {}
    module_counts: dict[str, int] = {}
    for f in findings:
        sev = f.severity.value
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
        module_counts[f.module_name] = module_counts.get(f.module_name, 0) + 1

    return {
        "scan_id": scan_id,
        "total_findings": len(findings),
        "by_severity": severity_counts,
        "by_module": module_counts,
    }
