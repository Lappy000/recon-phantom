"""
Async scan orchestration engine.

Manages scan lifecycle, module execution, concurrency control,
and coordinates between scanners, event bus, and storage.
"""

from __future__ import annotations

import asyncio
import time
import traceback
from datetime import datetime
from typing import Any, Optional, Type
from uuid import UUID, uuid4

import orjson

from recon_phantom.config import Settings, get_settings
from recon_phantom.core.database import get_session
from recon_phantom.core.events import EventBus, EventType, ScanEvent, get_event_bus
from recon_phantom.core.models import Scan, ScanResult, ScanStatus, Severity, Target


class ScanTask:
    """Represents a single scan task in the engine queue."""

    def __init__(
        self,
        scan_id: UUID,
        target: str,
        target_type: str,
        modules: list[str],
        config: dict[str, Any] | None = None,
    ):
        self.scan_id = scan_id
        self.target = target
        self.target_type = target_type
        self.modules = modules
        self.config = config or {}
        self.created_at = time.time()
        self.cancelled = False

    def cancel(self) -> None:
        """Mark this task as cancelled."""
        self.cancelled = True


class ScanEngine:
    """
    Main scan orchestration engine.
    
    Responsibilities:
    - Queue management for incoming scan requests
    - Concurrency control (limit parallel scans)
    - Module lifecycle management (start, monitor, stop)
    - Result aggregation and persistence
    - Event emission for real-time updates
    """

    def __init__(self, settings: Settings | None = None, event_bus: EventBus | None = None):
        self._settings = settings or get_settings()
        self._event_bus = event_bus or get_event_bus()
        self._task_queue: asyncio.Queue[ScanTask] = asyncio.Queue()
        self._active_scans: dict[UUID, ScanTask] = {}
        self._scan_semaphore = asyncio.Semaphore(self._settings.engine.max_concurrent_scans)
        self._running = False
        self._workers: list[asyncio.Task] = []
        self._scanner_registry: dict[str, Type] = {}

    def register_scanner(self, name: str, scanner_class: Type) -> None:
        """Register a scanner module by name."""
        self._scanner_registry[name] = scanner_class

    @property
    def registered_modules(self) -> list[str]:
        """List registered scanner module names."""
        return list(self._scanner_registry.keys())

    @property
    def active_scan_count(self) -> int:
        """Number of currently running scans."""
        return len(self._active_scans)

    @property
    def queue_size(self) -> int:
        """Number of scans waiting in queue."""
        return self._task_queue.qsize()

    async def start(self, num_workers: int = 3) -> None:
        """Start the scan engine with worker tasks."""
        if self._running:
            return

        self._running = True
        for i in range(num_workers):
            worker = asyncio.create_task(self._worker_loop(f"worker-{i}"))
            self._workers.append(worker)

        await self._event_bus.emit(ScanEvent(
            event_type=EventType.ENGINE_IDLE,
            data={"workers": num_workers, "max_concurrent": self._settings.engine.max_concurrent_scans},
        ))

    async def stop(self) -> None:
        """Stop the scan engine gracefully."""
        self._running = False
        for worker in self._workers:
            worker.cancel()
        await asyncio.gather(*self._workers, return_exceptions=True)
        self._workers.clear()

    async def submit_scan(
        self,
        target: str,
        target_type: str = "domain",
        modules: list[str] | None = None,
        config: dict[str, Any] | None = None,
    ) -> UUID:
        """
        Submit a new scan to the engine.
        
        Args:
            target: The scan target (domain, IP, URL, or CIDR)
            target_type: Type of target (domain, ip, url, cidr)
            modules: List of scanner modules to run (None = all registered)
            config: Per-scan configuration overrides
            
        Returns:
            UUID of the created scan
        """
        if modules is None:
            modules = list(self._scanner_registry.keys())

        # Validate modules
        invalid = [m for m in modules if m not in self._scanner_registry]
        if invalid:
            raise ValueError(f"Unknown scanner modules: {invalid}")

        scan_id = uuid4()

        # Persist to database
        async with get_session() as session:
            # Create or find target
            db_target = Target(
                value=target,
                target_type=target_type,
            )
            session.add(db_target)
            await session.flush()

            # Create scan record
            db_scan = Scan(
                id=str(scan_id),
                target_id=db_target.id,
                status=ScanStatus.PENDING,
                modules=orjson.dumps(modules).decode(),
                config_json=orjson.dumps(config).decode() if config else None,
            )
            session.add(db_scan)

        # Create task and enqueue
        task = ScanTask(
            scan_id=scan_id,
            target=target,
            target_type=target_type,
            modules=modules,
            config=config,
        )
        await self._task_queue.put(task)

        # Emit event
        await self._event_bus.emit(ScanEvent(
            event_type=EventType.SCAN_CREATED,
            scan_id=scan_id,
            data={"target": target, "modules": modules},
        ))

        return scan_id

    async def cancel_scan(self, scan_id: UUID) -> bool:
        """Cancel a running or queued scan."""
        if scan_id in self._active_scans:
            self._active_scans[scan_id].cancel()
            await self._update_scan_status(scan_id, ScanStatus.CANCELLED)
            await self._event_bus.emit(ScanEvent(
                event_type=EventType.SCAN_CANCELLED,
                scan_id=scan_id,
            ))
            return True
        return False

    async def get_scan_status(self, scan_id: UUID) -> dict[str, Any] | None:
        """Get current status of a scan."""
        async with get_session() as session:
            from sqlalchemy import select
            result = await session.execute(
                select(Scan).where(Scan.id == str(scan_id))
            )
            scan = result.scalar_one_or_none()
            if scan is None:
                return None
            return {
                "id": scan.id,
                "status": scan.status.value,
                "progress": scan.progress_percent,
                "current_module": scan.current_module,
                "total_findings": scan.total_findings,
                "started_at": scan.started_at.isoformat() if scan.started_at else None,
                "duration": scan.duration_seconds,
            }

    async def _worker_loop(self, worker_name: str) -> None:
        """Worker coroutine that processes scan tasks from the queue."""
        while self._running:
            try:
                task = await asyncio.wait_for(self._task_queue.get(), timeout=1.0)
            except asyncio.TimeoutError:
                continue
            except asyncio.CancelledError:
                break

            if task.cancelled:
                continue

            async with self._scan_semaphore:
                self._active_scans[task.scan_id] = task
                try:
                    await self._execute_scan(task)
                except Exception as e:
                    await self._handle_scan_failure(task, e)
                finally:
                    self._active_scans.pop(task.scan_id, None)

    async def _execute_scan(self, task: ScanTask) -> None:
        """Execute all modules for a scan task."""
        scan_id = task.scan_id
        start_time = time.time()

        # Update status to running
        await self._update_scan_status(scan_id, ScanStatus.RUNNING)
        await self._event_bus.emit(ScanEvent(
            event_type=EventType.SCAN_STARTED,
            scan_id=scan_id,
            data={"target": task.target, "modules": task.modules},
        ))

        all_results: list[dict[str, Any]] = []
        total_modules = len(task.modules)

        for idx, module_name in enumerate(task.modules):
            if task.cancelled:
                break

            # Update current module
            await self._update_scan_progress(scan_id, module_name, (idx / total_modules) * 100)

            await self._event_bus.emit(ScanEvent(
                event_type=EventType.SCAN_MODULE_STARTED,
                scan_id=scan_id,
                module_name=module_name,
                data={"index": idx, "total": total_modules},
            ))

            try:
                scanner_class = self._scanner_registry[module_name]
                scanner = scanner_class(
                    target=task.target,
                    target_type=task.target_type,
                    config=task.config.get(module_name, {}),
                    event_bus=self._event_bus,
                    scan_id=scan_id,
                    settings=self._settings,
                )

                results = await asyncio.wait_for(
                    scanner.run(),
                    timeout=self._settings.engine.default_timeout * 10,
                )

                all_results.extend(results)

                await self._event_bus.emit(ScanEvent(
                    event_type=EventType.SCAN_MODULE_COMPLETED,
                    scan_id=scan_id,
                    module_name=module_name,
                    data={"findings_count": len(results)},
                ))

            except asyncio.TimeoutError:
                await self._event_bus.emit(ScanEvent(
                    event_type=EventType.SCAN_MODULE_FAILED,
                    scan_id=scan_id,
                    module_name=module_name,
                    data={"error": "Module timed out"},
                    severity="warning",
                ))
            except Exception as e:
                await self._event_bus.emit(ScanEvent(
                    event_type=EventType.SCAN_MODULE_FAILED,
                    scan_id=scan_id,
                    module_name=module_name,
                    data={"error": str(e), "traceback": traceback.format_exc()},
                    severity="error",
                ))

        # Calculate duration
        duration = time.time() - start_time

        # Persist results
        await self._save_results(scan_id, all_results)

        # Finalize
        final_status = ScanStatus.CANCELLED if task.cancelled else ScanStatus.COMPLETED
        await self._finalize_scan(scan_id, final_status, duration, len(all_results))

        await self._event_bus.emit(ScanEvent(
            event_type=EventType.SCAN_COMPLETED,
            scan_id=scan_id,
            data={
                "duration_seconds": round(duration, 2),
                "total_findings": len(all_results),
                "critical": sum(1 for r in all_results if r.get("severity") == "critical"),
                "high": sum(1 for r in all_results if r.get("severity") == "high"),
            },
        ))

    async def _handle_scan_failure(self, task: ScanTask, error: Exception) -> None:
        """Handle unrecoverable scan failure."""
        await self._update_scan_status(
            task.scan_id,
            ScanStatus.FAILED,
            error_message=str(error),
        )
        await self._event_bus.emit(ScanEvent(
            event_type=EventType.SCAN_FAILED,
            scan_id=task.scan_id,
            data={"error": str(error), "traceback": traceback.format_exc()},
            severity="error",
        ))

    async def _update_scan_status(
        self, scan_id: UUID, status: ScanStatus, error_message: str | None = None
    ) -> None:
        """Update scan status in database."""
        async with get_session() as session:
            from sqlalchemy import update
            values: dict[str, Any] = {"status": status}
            if status == ScanStatus.RUNNING:
                values["started_at"] = datetime.utcnow()
            if error_message:
                values["error_message"] = error_message
            await session.execute(
                update(Scan).where(Scan.id == str(scan_id)).values(**values)
            )

    async def _update_scan_progress(
        self, scan_id: UUID, current_module: str, progress: float
    ) -> None:
        """Update scan progress in database."""
        async with get_session() as session:
            from sqlalchemy import update
            await session.execute(
                update(Scan).where(Scan.id == str(scan_id)).values(
                    current_module=current_module,
                    progress_percent=progress,
                )
            )

    async def _save_results(self, scan_id: UUID, results: list[dict[str, Any]]) -> None:
        """Persist scan results to database."""
        async with get_session() as session:
            for result in results:
                db_result = ScanResult(
                    scan_id=str(scan_id),
                    module_name=result.get("module", "unknown"),
                    severity=Severity(result.get("severity", "info")),
                    title=result.get("title", "Untitled Finding"),
                    description=result.get("description"),
                    evidence=result.get("evidence"),
                    remediation=result.get("remediation"),
                    data_json=orjson.dumps(result.get("data", {})).decode(),
                    host=result.get("host"),
                    port=result.get("port"),
                    path=result.get("path"),
                    protocol=result.get("protocol"),
                    confidence=result.get("confidence", 1.0),
                    cve_ids=",".join(result.get("cve_ids", [])),
                )
                session.add(db_result)

    async def _finalize_scan(
        self, scan_id: UUID, status: ScanStatus, duration: float, total_findings: int
    ) -> None:
        """Finalize scan with completion data."""
        async with get_session() as session:
            from sqlalchemy import update
            await session.execute(
                update(Scan).where(Scan.id == str(scan_id)).values(
                    status=status,
                    completed_at=datetime.utcnow(),
                    duration_seconds=duration,
                    progress_percent=100.0,
                    total_findings=total_findings,
                )
            )
