"""Application configuration via pydantic-settings."""

from __future__ import annotations

from enum import Enum
from pathlib import Path
from typing import Optional

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class LogLevel(str, Enum):
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"


class StealthConfig(BaseSettings):
    """Stealth/evasion configuration."""

    enabled: bool = True
    min_delay: float = Field(default=0.3, ge=0.0, description="Minimum delay between requests (seconds)")
    max_delay: float = Field(default=1.5, ge=0.0, description="Maximum delay between requests (seconds)")
    rotate_user_agents: bool = True
    randomize_order: bool = True
    proxy_list_path: Optional[Path] = None
    max_retries: int = 3
    retry_backoff_factor: float = 1.5
    jitter_factor: float = 0.2

    @field_validator("max_delay")
    @classmethod
    def max_delay_gte_min(cls, v: float, info) -> float:
        min_delay = info.data.get("min_delay", 0.0)
        if v < min_delay:
            raise ValueError("max_delay must be >= min_delay")
        return v


class EngineConfig(BaseSettings):
    """Scan engine configuration."""

    max_concurrent_scans: int = Field(default=3, ge=1, le=50)
    max_tasks_per_scan: int = Field(default=200, ge=1, le=10000)
    default_timeout: float = Field(default=30.0, ge=1.0)
    connection_timeout: float = Field(default=10.0, ge=1.0)
    max_connections_per_host: int = Field(default=20, ge=1, le=500)
    dns_timeout: float = Field(default=5.0, ge=1.0)
    follow_redirects: bool = True
    max_redirects: int = 10
    verify_ssl: bool = False


class ReportingConfig(BaseSettings):
    """Report generation configuration."""

    auto_save: bool = True
    output_dir: Path = Path("./reports")
    default_format: str = "html"
    include_raw_responses: bool = False
    max_evidence_size: int = 10240


class ScannerDefaults(BaseSettings):
    """Default scanner-specific settings."""

    # Port scanner
    port_scan_top_ports: int = 1000
    port_scan_timeout: float = 3.0
    port_scan_concurrent: int = 500

    # Subdomain
    subdomain_wordlist: str = "builtin:top1000"
    subdomain_resolvers: list[str] = Field(default_factory=lambda: [
        "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1",
        "9.9.9.9", "208.67.222.222", "208.67.220.220",
    ])
    subdomain_concurrent: int = 100

    # Directory bruteforce
    dirbrute_wordlist: str = "builtin:common"
    dirbrute_concurrent: int = 50
    dirbrute_extensions: list[str] = Field(default_factory=lambda: [
        ".php", ".asp", ".aspx", ".jsp", ".html", ".js", ".json",
        ".xml", ".txt", ".bak", ".old", ".conf", ".env", ".yml",
    ])
    dirbrute_follow_redirects: bool = False
    dirbrute_exclude_status: list[int] = Field(default_factory=lambda: [404, 403, 429, 503])

    # SSL
    ssl_check_revocation: bool = True
    ssl_check_ct_logs: bool = True

    # Tech fingerprint
    tech_fp_max_depth: int = 2


class Settings(BaseSettings):
    """Main application settings."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        env_prefix="RECON_",
        extra="ignore",
    )

    # General
    app_name: str = "Recon Phantom"
    debug: bool = False
    log_level: LogLevel = LogLevel.INFO
    data_dir: Path = Field(default=Path("./data"))

    # Database
    database_url: str = "sqlite+aiosqlite:///./data/recon.db"

    # API
    api_host: str = "0.0.0.0"
    api_port: int = 8080
    api_secret_key: str = Field(default="change-me-in-production")
    api_cors_origins: list[str] = Field(default_factory=lambda: ["*"])

    # Sub-configs
    engine: EngineConfig = Field(default_factory=EngineConfig)
    stealth: StealthConfig = Field(default_factory=StealthConfig)
    reporting: ReportingConfig = Field(default_factory=ReportingConfig)
    scanner_defaults: ScannerDefaults = Field(default_factory=ScannerDefaults)

    def ensure_dirs(self) -> None:
        """Create required directories."""
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.reporting.output_dir.mkdir(parents=True, exist_ok=True)


# Global settings singleton
_settings: Optional[Settings] = None


def get_settings() -> Settings:
    """Get or create the global settings instance."""
    global _settings
    if _settings is None:
        _settings = Settings()
        _settings.ensure_dirs()
    return _settings


def override_settings(settings: Settings) -> None:
    """Override global settings (for testing)."""
    global _settings
    _settings = settings
