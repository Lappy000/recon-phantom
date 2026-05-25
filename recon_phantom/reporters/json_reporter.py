"""JSON report exporter."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from recon_phantom.reporters.base import BaseReporter


class JsonReporter(BaseReporter):
    """Export scan results as formatted JSON.

    Produces a structured JSON document with metadata, summary statistics,
    and detailed findings suitable for automated processing.
    """

    @property
    def format_name(self) -> str:
        return "json"

    @property
    def file_extension(self) -> str:
        return ".json"

    def generate(self, findings: list[dict[str, Any]], **kwargs: Any) -> str:
        """Generate a JSON report from findings.

        Args:
            findings: List of finding dictionaries.
            **kwargs: Optional scan_id, target, metadata.

        Returns:
            Formatted JSON string.
        """
        # Calculate severity summary
        severity_counts: dict[str, int] = {}
        for finding in findings:
            sev = finding.get("severity", "info")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        # Build module summary
        module_counts: dict[str, int] = {}
        for finding in findings:
            mod = finding.get("module", "unknown")
            module_counts[mod] = module_counts.get(mod, 0) + 1

        report = {
            "metadata": {
                "generator": "Recon Phantom",
                "version": "1.0.0",
                "generated_at": datetime.utcnow().isoformat() + "Z",
                "scan_id": kwargs.get("scan_id"),
                "target": kwargs.get("target"),
            },
            "summary": {
                "total_findings": len(findings),
                "by_severity": severity_counts,
                "by_module": module_counts,
            },
            "findings": findings,
        }

        return json.dumps(report, indent=2, default=str, ensure_ascii=False)
