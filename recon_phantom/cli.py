"""Recon Phantom CLI - Beautiful command-line interface using Typer + Rich.

Provides commands for running scans, managing the API server,
generating reports, and monitoring scan status.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from typing import Optional
from uuid import UUID

import typer
from rich import print as rprint
from rich.columns import Columns
from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
    TimeRemainingColumn,
)
from rich.table import Table
from rich.text import Text
from rich.tree import Tree

from recon_phantom import __version__

app = typer.Typer(
    name="recon-phantom",
    help="🕵️ Recon Phantom - Async multi-engine reconnaissance & vulnerability scanner",
    no_args_is_help=True,
    rich_markup_mode="rich",
)
console = Console()

# Severity color mapping
SEVERITY_COLORS = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "cyan",
    "info": "dim white",
}


def _get_severity_style(severity: str) -> str:
    """Get Rich style string for a severity level."""
    return SEVERITY_COLORS.get(severity.lower(), "white")


def _print_banner() -> None:
    """Print the application banner."""
    banner = """
[bold cyan]╔══════════════════════════════════════════════════╗
║[/bold cyan] [bold white]   ____                        ____  _                 _                [/bold white] [bold cyan]║
║[/bold cyan] [bold white]  |  _ \\ ___  ___ ___  _ __   |  _ \\| |__   __ _ _ __ | |_ ___  _ __ [/bold white]  [bold cyan]║
║[/bold cyan] [bold white]  | |_) / _ \\/ __/ _ \\| '_ \\  | |_) | '_ \\ / _` | '_ \\| __/ _ \\| '_ \\ [/bold white] [bold cyan]║
║[/bold cyan] [bold white]  |  _ <  __/ (_| (_) | | | | |  __/| | | | (_| | | | | || (_) | | | |[/bold white] [bold cyan]║
║[/bold cyan] [bold white]  |_| \\_\\___|\\___\\___/|_| |_| |_|   |_| |_|\\__,_|_| |_|\\__\\___/|_| |_|[/bold white] [bold cyan]║
║[/bold cyan]                                                                       [bold cyan]║
╚══════════════════════════════════════════════════╝[/bold cyan]
    """
    rprint(banner)
    rprint(f"  [dim]v{__version__} • Async Reconnaissance Framework[/dim]\n")


@app.command()
def scan(
    target: str = typer.Argument(..., help="Target to scan (domain, IP, CIDR, or URL)"),
    modules: Optional[str] = typer.Option(
        None, "--modules", "-m",
        help="Comma-separated list of modules to run (default: all)",
    ),
    output: Optional[Path] = typer.Option(
        None, "--output", "-o",
        help="Output file path for results",
    ),
    output_format: str = typer.Option(
        "json", "--format", "-f",
        help="Output format: json, html, csv",
    ),
    ports: Optional[str] = typer.Option(
        None, "--ports", "-p",
        help="Port specification (e.g., '80,443,8080' or '1-1024')",
    ),
    timeout: float = typer.Option(
        30.0, "--timeout", "-t",
        help="Per-module timeout in seconds",
    ),
    concurrency: int = typer.Option(
        50, "--concurrency", "-c",
        help="Maximum concurrent operations per module",
    ),
    stealth: bool = typer.Option(
        True, "--stealth/--no-stealth",
        help="Enable stealth mode (random delays, UA rotation)",
    ),
    verbose: bool = typer.Option(
        False, "--verbose", "-v",
        help="Verbose output showing detailed progress",
    ),
) -> None:
    """🎯 Launch a reconnaissance scan against a target.

    Runs specified scanner modules against the target with real-time
    progress display and rich result summaries.
    """
    _print_banner()

    console.print(f"[bold green]🎯 Target:[/bold green] {target}")

    # Parse modules
    module_list: list[str] | None = None
    if modules:
        module_list = [m.strip() for m in modules.split(",")]
        console.print(f"[bold blue]📦 Modules:[/bold blue] {', '.join(module_list)}")
    else:
        console.print("[bold blue]📦 Modules:[/bold blue] All registered modules")

    if stealth:
        console.print("[bold yellow]🥷 Stealth:[/bold yellow] Enabled (random delays + UA rotation)")

    console.print()

    # Run scan with progress display
    try:
        results = asyncio.run(_run_scan(
            target=target,
            modules=module_list,
            ports=ports,
            timeout=timeout,
            concurrency=concurrency,
            stealth=stealth,
            verbose=verbose,
        ))
    except KeyboardInterrupt:
        console.print("\n[bold red]⚠️  Scan cancelled by user[/bold red]")
        raise typer.Exit(1)
    except Exception as e:
        console.print(f"\n[bold red]❌ Scan failed: {e}[/bold red]")
        raise typer.Exit(1)

    # Display results summary
    _display_results_summary(results)

    # Save output if requested
    if output:
        _save_results(results, output, output_format)
        console.print(f"\n[bold green]💾 Results saved to:[/bold green] {output}")


async def _run_scan(
    target: str,
    modules: list[str] | None,
    ports: str | None,
    timeout: float,
    concurrency: int,
    stealth: bool,
    verbose: bool,
) -> list[dict]:
    """Execute scan with progress tracking."""
    from recon_phantom.config import get_settings
    from recon_phantom.core.database import init_database
    from recon_phantom.core.engine import ScanEngine
    from recon_phantom.core.events import EventType, get_event_bus

    # Import scanner classes
    from recon_phantom.scanners.port_scanner import PortScanner

    settings = get_settings()
    await init_database()

    engine = ScanEngine(settings=settings)
    engine.register_scanner("port_scanner", PortScanner)

    # Try to register other scanners (they may not all be available)
    try:
        from recon_phantom.scanners.subdomain import SubdomainScanner
        engine.register_scanner("subdomain", SubdomainScanner)
    except (ImportError, Exception):
        pass
    try:
        from recon_phantom.scanners.dns_recon import DnsReconScanner
        engine.register_scanner("dns_recon", DnsReconScanner)
    except (ImportError, Exception):
        pass
    try:
        from recon_phantom.scanners.ssl_analyzer import SslAnalyzer
        engine.register_scanner("ssl_analyzer", SslAnalyzer)
    except (ImportError, Exception):
        pass
    try:
        from recon_phantom.scanners.tech_fingerprint import TechFingerprint
        engine.register_scanner("tech_fingerprint", TechFingerprint)
    except (ImportError, Exception):
        pass
    try:
        from recon_phantom.scanners.directory_bruteforce import DirectoryBruteforce
        engine.register_scanner("directory_bruteforce", DirectoryBruteforce)
    except (ImportError, Exception):
        pass
    try:
        from recon_phantom.scanners.cve_lookup import CveLookup
        engine.register_scanner("cve_lookup", CveLookup)
    except (ImportError, Exception):
        pass

    # Filter to requested modules
    if modules:
        available = engine.registered_modules
        invalid = [m for m in modules if m not in available]
        if invalid:
            console.print(f"[bold red]Unknown modules: {invalid}[/bold red]")
            console.print(f"[dim]Available: {available}[/dim]")
            raise typer.Exit(1)

    # Configure scan
    config: dict = {"timeout": timeout, "concurrency": concurrency}
    if ports:
        config["ports"] = ports
    if not stealth:
        config["min_delay"] = 0.0
        config["max_delay"] = 0.0

    # Determine target type
    from recon_phantom.utils.network import is_valid_cidr, is_valid_ip

    if is_valid_ip(target):
        target_type = "ip"
    elif is_valid_cidr(target):
        target_type = "cidr"
    elif target.startswith(("http://", "https://")):
        target_type = "url"
    else:
        target_type = "domain"

    # Start engine and execute
    await engine.start(num_workers=1)

    # Track progress
    event_bus = get_event_bus()
    progress_data: dict = {"current_module": "", "progress": 0, "findings": []}

    async def on_module_started(event):
        progress_data["current_module"] = event.module_name or ""

    async def on_finding(event):
        progress_data["findings"].append(event.data)

    event_bus.subscribe(EventType.SCAN_MODULE_STARTED, on_module_started)
    event_bus.subscribe(EventType.FINDING_NEW, on_finding)

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("[cyan]Scanning...", total=100)

        scan_id = await engine.submit_scan(
            target=target,
            target_type=target_type,
            modules=modules or engine.registered_modules,
            config=config,
        )

        # Wait for completion
        while True:
            status = await engine.get_scan_status(scan_id)
            if status is None:
                break
            pct = status.get("progress", 0)
            progress.update(task, completed=pct, description=f"[cyan]{status.get('current_module', 'Scanning')}...")
            if status["status"] in ("completed", "failed", "cancelled"):
                progress.update(task, completed=100)
                break
            await asyncio.sleep(0.5)

    await engine.stop()

    # Fetch results from database
    from recon_phantom.core.database import get_session
    from recon_phantom.core.models import ScanResult
    from sqlalchemy import select

    results = []
    async with get_session() as session:
        query = select(ScanResult).where(ScanResult.scan_id == str(scan_id))
        result = await session.execute(query)
        for row in result.scalars():
            results.append({
                "title": row.title,
                "severity": row.severity.value,
                "module": row.module_name,
                "host": row.host,
                "port": row.port,
                "description": row.description,
                "evidence": row.evidence,
            })

    return results


def _display_results_summary(results: list[dict]) -> None:
    """Display a rich summary table of scan results."""
    if not results:
        console.print("\n[bold green]✅ Scan complete - No findings[/bold green]")
        return

    # Severity counts
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for r in results:
        sev = r.get("severity", "info").lower()
        counts[sev] = counts.get(sev, 0) + 1

    # Summary panel
    summary_parts = []
    for sev, count in counts.items():
        if count > 0:
            style = _get_severity_style(sev)
            summary_parts.append(f"[{style}]{sev.upper()}: {count}[/{style}]")

    console.print(Panel(
        " │ ".join(summary_parts),
        title="[bold]📊 Findings Summary[/bold]",
        border_style="green",
    ))

    # Results table
    table = Table(
        show_header=True,
        header_style="bold magenta",
        border_style="dim",
        title="Scan Results",
    )
    table.add_column("Severity", style="bold", width=10)
    table.add_column("Module", style="cyan", width=18)
    table.add_column("Title", width=40)
    table.add_column("Host", style="green", width=20)
    table.add_column("Port", style="yellow", width=6)

    for r in sorted(results, key=lambda x: list(SEVERITY_COLORS.keys()).index(x.get("severity", "info"))):
        sev = r.get("severity", "info")
        style = _get_severity_style(sev)
        table.add_row(
            f"[{style}]{sev.upper()}[/{style}]",
            r.get("module", ""),
            r.get("title", "")[:40],
            r.get("host", ""),
            str(r.get("port", "")) if r.get("port") else "",
        )

    console.print(table)
    console.print(f"\n[bold]Total findings: {len(results)}[/bold]")


def _save_results(results: list[dict], output: Path, fmt: str) -> None:
    """Save results to a file in the specified format."""
    import json

    output.parent.mkdir(parents=True, exist_ok=True)

    if fmt == "json":
        output.write_text(json.dumps(results, indent=2, default=str))
    elif fmt == "html":
        from recon_phantom.reporters.html_reporter import HtmlReporter
        reporter = HtmlReporter()
        html = reporter.generate(results)
        output.write_text(html)
    else:
        # Default to JSON
        output.write_text(json.dumps(results, indent=2, default=str))


@app.command()
def serve(
    host: str = typer.Option("0.0.0.0", "--host", "-h", help="API server host"),
    port: int = typer.Option(8080, "--port", "-p", help="API server port"),
    reload: bool = typer.Option(False, "--reload", help="Enable auto-reload for development"),
    workers: int = typer.Option(1, "--workers", "-w", help="Number of worker processes"),
) -> None:
    """🌐 Start the REST API server.

    Launches the FastAPI server with WebSocket support for real-time
    scan monitoring and control.
    """
    _print_banner()
    console.print(f"[bold green]🌐 Starting API server[/bold green]")
    console.print(f"   Host: [cyan]{host}[/cyan]")
    console.print(f"   Port: [cyan]{port}[/cyan]")
    console.print(f"   Docs: [link]http://{host}:{port}/docs[/link]")
    console.print()

    try:
        import uvicorn
        uvicorn.run(
            "recon_phantom.api.app:create_app",
            host=host,
            port=port,
            reload=reload,
            workers=workers,
            factory=True,
            log_level="info",
        )
    except ImportError:
        console.print("[bold red]❌ uvicorn not installed. Run: pip install uvicorn[/bold red]")
        raise typer.Exit(1)


@app.command()
def report(
    scan_id: str = typer.Argument(..., help="Scan ID to generate report for"),
    output_format: str = typer.Option(
        "html", "--format", "-f",
        help="Report format: html, json",
    ),
    output: Optional[Path] = typer.Option(
        None, "--output", "-o",
        help="Output file path (default: ./reports/<scan_id>.<format>)",
    ),
) -> None:
    """📄 Generate a report from a completed scan.

    Creates a formatted report from scan results stored in the database.
    """
    console.print(f"[bold]📄 Generating {output_format.upper()} report for scan {scan_id[:8]}...[/bold]")

    try:
        results = asyncio.run(_fetch_scan_results(scan_id))
    except Exception as e:
        console.print(f"[bold red]❌ Failed to fetch results: {e}[/bold red]")
        raise typer.Exit(1)

    if not results:
        console.print("[yellow]⚠️  No results found for this scan ID[/yellow]")
        raise typer.Exit(0)

    # Determine output path
    if output is None:
        output = Path(f"./reports/{scan_id[:8]}.{output_format}")

    _save_results(results, output, output_format)
    console.print(f"[bold green]✅ Report saved to: {output}[/bold green]")


async def _fetch_scan_results(scan_id: str) -> list[dict]:
    """Fetch scan results from database."""
    from recon_phantom.core.database import init_database, get_session
    from recon_phantom.core.models import ScanResult
    from sqlalchemy import select

    await init_database()
    results = []
    async with get_session() as session:
        query = select(ScanResult).where(ScanResult.scan_id == scan_id)
        result = await session.execute(query)
        for row in result.scalars():
            results.append({
                "title": row.title,
                "severity": row.severity.value,
                "module": row.module_name,
                "host": row.host,
                "port": row.port,
                "description": row.description,
                "evidence": row.evidence,
            })
    return results


@app.command()
def status(
    scan_id: Optional[str] = typer.Argument(None, help="Scan ID to check (shows all if omitted)"),
) -> None:
    """📊 Show status of active and recent scans."""
    console.print("[bold]📊 Scan Status[/bold]\n")

    try:
        scans = asyncio.run(_fetch_scans(scan_id))
    except Exception as e:
        console.print(f"[bold red]❌ Error: {e}[/bold red]")
        raise typer.Exit(1)

    if not scans:
        console.print("[dim]No scans found.[/dim]")
        return

    table = Table(show_header=True, header_style="bold magenta", border_style="dim")
    table.add_column("ID", style="cyan", width=10)
    table.add_column("Status", width=12)
    table.add_column("Target", style="green", width=25)
    table.add_column("Progress", width=10)
    table.add_column("Findings", width=10)
    table.add_column("Duration", width=10)
    table.add_column("Started", style="dim", width=20)

    status_styles = {
        "pending": "yellow",
        "running": "bold cyan",
        "completed": "green",
        "failed": "red",
        "cancelled": "dim",
    }

    for s in scans:
        status_str = s["status"]
        style = status_styles.get(status_str, "white")
        table.add_row(
            s["id"][:8] + "...",
            f"[{style}]{status_str.upper()}[/{style}]",
            s.get("target", ""),
            f"{s.get('progress', 0):.0f}%",
            str(s.get("findings", 0)),
            f"{s.get('duration', 0):.1f}s" if s.get("duration") else "-",
            s.get("started_at", "-"),
        )

    console.print(table)


async def _fetch_scans(scan_id: Optional[str] = None) -> list[dict]:
    """Fetch scan records from database."""
    from recon_phantom.core.database import init_database, get_session
    from recon_phantom.core.models import Scan, Target
    from sqlalchemy import select
    from sqlalchemy.orm import selectinload

    await init_database()
    results = []
    async with get_session() as session:
        query = select(Scan).options(selectinload(Scan.target)).order_by(Scan.created_at.desc()).limit(20)
        if scan_id:
            query = select(Scan).options(selectinload(Scan.target)).where(Scan.id == scan_id)
        result = await session.execute(query)
        for scan in result.scalars():
            results.append({
                "id": scan.id,
                "status": scan.status.value,
                "target": scan.target.value if scan.target else "",
                "progress": scan.progress_percent,
                "findings": scan.total_findings,
                "duration": scan.duration_seconds,
                "started_at": scan.started_at.isoformat() if scan.started_at else None,
            })
    return results


@app.command(name="list-modules")
def list_modules() -> None:
    """📦 List all available scanner modules."""
    _print_banner()

    modules_info = [
        ("port_scanner", "TCP port scanning with banner grabbing and service fingerprinting", "🔌"),
        ("subdomain", "Subdomain enumeration via DNS bruteforce and public sources", "🌐"),
        ("dns_recon", "DNS reconnaissance - zone transfers, record enumeration", "📡"),
        ("ssl_analyzer", "SSL/TLS certificate and configuration analysis", "🔒"),
        ("tech_fingerprint", "Web technology fingerprinting and stack detection", "🔍"),
        ("directory_bruteforce", "Directory and file discovery via bruteforce", "📂"),
        ("cve_lookup", "CVE vulnerability lookup for detected services", "⚠️"),
    ]

    table = Table(
        show_header=True,
        header_style="bold magenta",
        border_style="green",
        title="Available Scanner Modules",
    )
    table.add_column("", width=3)
    table.add_column("Module", style="bold cyan", width=22)
    table.add_column("Description", width=55)

    for name, desc, icon in modules_info:
        table.add_row(icon, name, desc)

    console.print(table)
    console.print(f"\n[dim]Use --modules flag to select specific modules: recon-phantom scan target.com -m port_scanner,subdomain[/dim]")


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    version: bool = typer.Option(False, "--version", "-V", help="Show version"),
) -> None:
    """Recon Phantom - Async multi-engine reconnaissance framework."""
    if version:
        rprint(f"[bold cyan]Recon Phantom[/bold cyan] v{__version__}")
        raise typer.Exit()

    if ctx.invoked_subcommand is None:
        _print_banner()
        console.print("[dim]Run 'recon-phantom --help' for usage information[/dim]")


if __name__ == "__main__":
    app()
