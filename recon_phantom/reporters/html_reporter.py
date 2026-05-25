"""HTML report generator with dark-theme inline CSS."""

from __future__ import annotations

from datetime import datetime
from html import escape
from typing import Any

from recon_phantom.reporters.base import BaseReporter


class HtmlReporter(BaseReporter):
    """Generate HTML reports with inline dark-theme CSS.

    Produces self-contained HTML files with embedded styles for
    portable, attractive vulnerability reports.
    """

    @property
    def format_name(self) -> str:
        return "html"

    @property
    def file_extension(self) -> str:
        return ".html"

    def generate(self, findings: list[dict[str, Any]], **kwargs: Any) -> str:
        """Generate an HTML report from findings.

        Args:
            findings: List of finding dictionaries.
            **kwargs: Optional scan_id, target.

        Returns:
            Complete HTML document string.
        """
        scan_id = kwargs.get("scan_id", "N/A")
        target = kwargs.get("target", "Unknown")
        generated_at = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

        # Calculate summary
        severity_counts: dict[str, int] = {}
        for f in findings:
            sev = f.get("severity", "info")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        # Build findings HTML
        findings_html = self._build_findings_table(findings)
        summary_html = self._build_summary_cards(severity_counts, len(findings))

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Recon Phantom Report - {escape(str(scan_id)[:8])}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #0d1117;
            color: #c9d1d9;
            line-height: 1.6;
            padding: 2rem;
        }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        h1 {{
            color: #58a6ff;
            font-size: 2rem;
            margin-bottom: 0.5rem;
            border-bottom: 1px solid #21262d;
            padding-bottom: 1rem;
        }}
        .meta {{
            color: #8b949e;
            font-size: 0.9rem;
            margin-bottom: 2rem;
        }}
        .summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }}
        .card {{
            background: #161b22;
            border: 1px solid #21262d;
            border-radius: 8px;
            padding: 1.2rem;
            text-align: center;
        }}
        .card .count {{
            font-size: 2rem;
            font-weight: bold;
            display: block;
        }}
        .card .label {{
            font-size: 0.85rem;
            color: #8b949e;
            text-transform: uppercase;
        }}
        .critical {{ color: #f85149; border-left: 4px solid #f85149; }}
        .high {{ color: #db6d28; border-left: 4px solid #db6d28; }}
        .medium {{ color: #d29922; border-left: 4px solid #d29922; }}
        .low {{ color: #58a6ff; border-left: 4px solid #58a6ff; }}
        .info {{ color: #8b949e; border-left: 4px solid #8b949e; }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 1rem;
            background: #161b22;
            border-radius: 8px;
            overflow: hidden;
        }}
        th {{
            background: #21262d;
            color: #c9d1d9;
            padding: 0.8rem 1rem;
            text-align: left;
            font-size: 0.85rem;
            text-transform: uppercase;
        }}
        td {{
            padding: 0.7rem 1rem;
            border-bottom: 1px solid #21262d;
            font-size: 0.9rem;
        }}
        tr:hover {{ background: #1c2128; }}
        .severity-badge {{
            padding: 0.2rem 0.6rem;
            border-radius: 12px;
            font-size: 0.75rem;
            font-weight: bold;
            text-transform: uppercase;
        }}
        .badge-critical {{ background: #3d1114; color: #f85149; }}
        .badge-high {{ background: #3d2008; color: #db6d28; }}
        .badge-medium {{ background: #3d2e04; color: #d29922; }}
        .badge-low {{ background: #0c2d6b; color: #58a6ff; }}
        .badge-info {{ background: #1c2128; color: #8b949e; }}
        .footer {{
            margin-top: 3rem;
            padding-top: 1rem;
            border-top: 1px solid #21262d;
            color: #484f58;
            font-size: 0.8rem;
            text-align: center;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🕵️ Recon Phantom Report</h1>
        <div class="meta">
            <strong>Scan ID:</strong> {escape(str(scan_id))} &nbsp;|&nbsp;
            <strong>Target:</strong> {escape(str(target))} &nbsp;|&nbsp;
            <strong>Generated:</strong> {generated_at} &nbsp;|&nbsp;
            <strong>Findings:</strong> {len(findings)}
        </div>

        {summary_html}

        <h2 style="color: #c9d1d9; margin-bottom: 1rem;">📋 Findings</h2>
        {findings_html}

        <div class="footer">
            Generated by Recon Phantom v1.0.0 &mdash; {generated_at}
        </div>
    </div>
</body>
</html>"""

    def _build_summary_cards(self, severity_counts: dict[str, int], total: int) -> str:
        """Build HTML for summary stat cards."""
        cards = [
            f'<div class="card"><span class="count">{total}</span><span class="label">Total</span></div>'
        ]

        severity_order = ["critical", "high", "medium", "low", "info"]
        for sev in severity_order:
            count = severity_counts.get(sev, 0)
            if count > 0:
                cards.append(
                    f'<div class="card {sev}"><span class="count">{count}</span>'
                    f'<span class="label">{sev}</span></div>'
                )

        return f'<div class="summary">{"".join(cards)}</div>'

    def _build_findings_table(self, findings: list[dict[str, Any]]) -> str:
        """Build HTML table for findings."""
        if not findings:
            return '<p style="color: #8b949e;">No findings to display.</p>'

        rows = []
        # Sort by severity priority
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        sorted_findings = sorted(
            findings,
            key=lambda f: severity_order.get(f.get("severity", "info"), 5),
        )

        for f in sorted_findings:
            sev = f.get("severity", "info")
            badge_class = f"badge-{sev}"
            rows.append(f"""<tr>
                <td><span class="severity-badge {badge_class}">{escape(sev)}</span></td>
                <td>{escape(str(f.get('module', '')))}</td>
                <td>{escape(str(f.get('title', '')))}</td>
                <td>{escape(str(f.get('host', '')))}</td>
                <td>{escape(str(f.get('port', '') if f.get('port') else ''))}</td>
                <td>{escape(str(f.get('description', '')[:80]))}</td>
            </tr>""")

        return f"""<table>
            <thead>
                <tr>
                    <th>Severity</th>
                    <th>Module</th>
                    <th>Title</th>
                    <th>Host</th>
                    <th>Port</th>
                    <th>Description</th>
                </tr>
            </thead>
            <tbody>
                {''.join(rows)}
            </tbody>
        </table>"""
