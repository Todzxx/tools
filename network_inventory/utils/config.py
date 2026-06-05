from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import BaseModel, Field


class ScannerConfig(BaseModel):
    allow_public: bool = False
    max_hosts: int = 1024
    timeout: float = 2.0
    use_nmap: bool = False
    use_ipv6: bool = False
    use_dhcp: bool = False
    use_snmp: bool = False
    snmp_communities: list[str] = ["public", "private"]
    db_path: str = "scan_history.db"


class RouterConfig(BaseModel):
    ip: str | None = None
    username: str = "admin"
    password: str = "admin"


class AppConfig(BaseModel):
    scanner: ScannerConfig = Field(default_factory=ScannerConfig)
    router: RouterConfig = Field(default_factory=RouterConfig)
    output_dir: str = "results"


class ConfigManager:
    """Manages YAML-based configuration for the application."""

    def __init__(self, config_path: str | Path | None = None):
        if config_path:
            self.path = Path(config_path)
        else:
            # Default to config.yaml in the project root or user home
            self.path = Path("config.yaml")

    def load(self) -> AppConfig:
        if not self.path.exists():
            return AppConfig()

        try:
            with open(self.path, "r") as f:
                data = yaml.safe_load(f) or {}
                return AppConfig(**data)
        except Exception:
            return AppConfig()

    def save(self, config: AppConfig) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.path, "w") as f:
            yaml.dump(config.model_dump(), f, default_flow_style=False)

    @staticmethod
    def get_default_path() -> Path:
        return Path("config.yaml")
