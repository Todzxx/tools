from __future__ import annotations

import platform
import shutil
from pathlib import Path


class DependencyChecker:
    """Checks for system dependencies required for advanced scanning features."""

    @staticmethod
    def is_nmap_installed() -> bool:
        if shutil.which("nmap") is not None:
            return True

        if platform.system() != "Windows":
            return False

        return any(
            p.exists()
            for p in [
                Path("C:/Program Files (x86)/Nmap/nmap.exe"),
                Path("C:/Program Files/Nmap/nmap.exe"),
            ]
        )

    @staticmethod
    def get_missing_dependencies() -> list[str]:
        missing = []
        if not DependencyChecker.is_nmap_installed():
            missing.append("Nmap (optional, for OS fingerprinting)")
        return missing
