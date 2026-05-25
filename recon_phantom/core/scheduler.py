"""Scan scheduling with cron expressions and retry logic."""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Optional
from uuid import UUID

from recon_phantom.core.engine import ScanEngine

logger = logging.getLogger(__name__)


class RetryPolicy:
    """Configurable retry policy for failed scans."""

    def __init__(
        self,
        max_retries: int = 3,
        backoff_factor: float = 2.0,
        initial_delay: float = 60.0,
        max_delay: float = 3600.0,
        retry_on_timeout: bool = True,
        retry_on_error: bool = True,
    ):
        self.max_retries = max_retries
        self.backoff_factor = backoff_factor
        self.initial_delay = initial_delay
        self.max_delay = max_delay
        self.retry_on_timeout = retry_on_timeout
        self.retry_on_error = retry_on_error

    def get_delay(self, attempt: int) -> float:
        """Calculate delay for given retry attempt (exponential backoff)."""
        delay = self.initial_delay * (self.backoff_factor ** attempt)
        return min(delay, self.max_delay)

    def should_retry(self, attempt: int, error_type: str) -> bool:
        """Determine if a retry should be attempted."""
        if attempt >= self.max_retries:
            return False
        if error_type == "timeout" and not self.retry_on_timeout:
            return False
        if error_type == "error" and not self.retry_on_error:
            return False
        return True


class ScheduledScan:
    """Represents a scheduled recurring scan."""

    def __init__(
        self,
        name: str,
        target: str,
        target_type: str,
        modules: list[str],
        interval_seconds: float,
        retry_policy: RetryPolicy | None = None,
        enabled: bool = True,
    ):
        self.name = name
        self.target = target
        self.target_type = target_type
        self.modules = modules
        self.interval_seconds = interval_seconds
        self.retry_policy = retry_policy or RetryPolicy()
        self.enabled = enabled
        self.last_run: Optional[datetime] = None
        self.next_run: Optional[datetime] = None
        self.consecutive_failures: int = 0
        self._task: Optional[asyncio.Task] = None

    @property
    def is_due(self) -> bool:
        """Check if this scheduled scan is due to run."""
        if not self.enabled:
            return False
        if self.next_run is None:
            return True
        return datetime.utcnow() >= self.next_run

    def update_schedule(self) -> None:
        """Update next_run after execution."""
        self.last_run = datetime.utcnow()
        self.next_run = self.last_run + timedelta(seconds=self.interval_seconds)


class ScanScheduler:
    """
    Manages scheduled/recurring scans.
    
    Runs a background loop that checks for due scans and submits them
    to the scan engine. Handles retries for failed scans.
    """

    def __init__(self, engine: ScanEngine, check_interval: float = 30.0):
        self._engine = engine
        self._check_interval = check_interval
        self._schedules: dict[str, ScheduledScan] = {}
        self._running = False
        self._loop_task: Optional[asyncio.Task] = None
        self._retry_queue: list[tuple[ScheduledScan, int, float]] = []  # (scan, attempt, run_after_ts)

    def add_schedule(self, schedule: ScheduledScan) -> None:
        """Add a new scheduled scan."""
        self._schedules[schedule.name] = schedule
        logger.info(f"Scheduled scan added: {schedule.name} (every {schedule.interval_seconds}s)")

    def remove_schedule(self, name: str) -> bool:
        """Remove a scheduled scan by name."""
        if name in self._schedules:
            del self._schedules[name]
            return True
        return False

    def pause_schedule(self, name: str) -> bool:
        """Pause a scheduled scan."""
        if name in self._schedules:
            self._schedules[name].enabled = False
            return True
        return False

    def resume_schedule(self, name: str) -> bool:
        """Resume a paused scheduled scan."""
        if name in self._schedules:
            self._schedules[name].enabled = True
            return True
        return False

    async def start(self) -> None:
        """Start the scheduler loop."""
        if self._running:
            return
        self._running = True
        self._loop_task = asyncio.create_task(self._scheduler_loop())
        logger.info("Scan scheduler started")

    async def stop(self) -> None:
        """Stop the scheduler loop."""
        self._running = False
        if self._loop_task:
            self._loop_task.cancel()
            try:
                await self._loop_task
            except asyncio.CancelledError:
                pass
        logger.info("Scan scheduler stopped")

    async def _scheduler_loop(self) -> None:
        """Main scheduler loop — checks for due scans periodically."""
        while self._running:
            try:
                await self._check_and_run_due_scans()
                await self._process_retry_queue()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Scheduler loop error: {e}")

            await asyncio.sleep(self._check_interval)

    async def _check_and_run_due_scans(self) -> None:
        """Check all schedules and submit due scans."""
        for schedule in self._schedules.values():
            if schedule.is_due:
                try:
                    scan_id = await self._engine.submit_scan(
                        target=schedule.target,
                        target_type=schedule.target_type,
                        modules=schedule.modules,
                    )
                    schedule.update_schedule()
                    schedule.consecutive_failures = 0
                    logger.info(f"Scheduled scan '{schedule.name}' submitted: {scan_id}")
                except Exception as e:
                    schedule.consecutive_failures += 1
                    logger.error(f"Failed to submit scheduled scan '{schedule.name}': {e}")

                    # Queue for retry
                    if schedule.retry_policy.should_retry(
                        schedule.consecutive_failures, "error"
                    ):
                        delay = schedule.retry_policy.get_delay(schedule.consecutive_failures)
                        retry_after = asyncio.get_event_loop().time() + delay
                        self._retry_queue.append((schedule, schedule.consecutive_failures, retry_after))

    async def _process_retry_queue(self) -> None:
        """Process pending retries."""
        now = asyncio.get_event_loop().time()
        ready = [(s, a, t) for s, a, t in self._retry_queue if t <= now]
        self._retry_queue = [(s, a, t) for s, a, t in self._retry_queue if t > now]

        for schedule, attempt, _ in ready:
            try:
                scan_id = await self._engine.submit_scan(
                    target=schedule.target,
                    target_type=schedule.target_type,
                    modules=schedule.modules,
                )
                schedule.consecutive_failures = 0
                logger.info(f"Retry successful for '{schedule.name}' (attempt {attempt}): {scan_id}")
            except Exception as e:
                logger.error(f"Retry failed for '{schedule.name}' (attempt {attempt}): {e}")
                if schedule.retry_policy.should_retry(attempt + 1, "error"):
                    delay = schedule.retry_policy.get_delay(attempt + 1)
                    self._retry_queue.append((schedule, attempt + 1, now + delay))

    @property
    def status(self) -> dict:
        """Get scheduler status summary."""
        return {
            "running": self._running,
            "total_schedules": len(self._schedules),
            "enabled_schedules": sum(1 for s in self._schedules.values() if s.enabled),
            "pending_retries": len(self._retry_queue),
            "schedules": [
                {
                    "name": s.name,
                    "target": s.target,
                    "enabled": s.enabled,
                    "interval_seconds": s.interval_seconds,
                    "last_run": s.last_run.isoformat() if s.last_run else None,
                    "next_run": s.next_run.isoformat() if s.next_run else None,
                    "failures": s.consecutive_failures,
                }
                for s in self._schedules.values()
            ],
        }
