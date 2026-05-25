"""Abstract base reporter for scan result output."""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Optional


class BaseReporter(ABC):
    """Abstract base class for scan result reporters.

    All reporter implementations must inherit from this class and
    implement the generate() and save() methods.
    """

    def __init__(self, output_dir: Optional[Path] = None) -> None:
        """Initialize the reporter.

        Args:
            output_dir: Directory for saving report files.
        """
        self.output_dir = output_dir or Path("./reports")

    @property
    @abstractmethod
    def format_name(self) -> str:
        """Return the report format identifier (e.g., 'json', 'html')."""
        ...

    @property
    @abstractmethod
    def file_extension(self) -> str:
        """Return the file extension for this format (e.g., '.json', '.html')."""
        ...

    @abstractmethod
    def generate(self, findings: list[dict[str, Any]], **kwargs: Any) -> str:
        """Generate report content from findings.

        Args:
            findings: List of finding dictionaries.
            **kwargs: Additional parameters (scan_id, target, etc.)

        Returns:
            Report content as string.
        """
        ...

    def save(self, findings: list[dict[str, Any]], filename: Optional[str] = None, **kwargs: Any) -> Path:
        """Generate and save report to file.

        Args:
            findings: List of finding dictionaries.
            filename: Custom filename (without extension).
            **kwargs: Additional parameters passed to generate().

        Returns:
            Path to the saved report file.
        """
        self.output_dir.mkdir(parents=True, exist_ok=True)

        if filename is None:
            import time
            filename = f"report-{int(time.time())}"

        filepath = self.output_dir / f"{filename}{self.file_extension}"
        content = self.generate(findings, **kwargs)
        filepath.write_text(content, encoding="utf-8")

        return filepath
