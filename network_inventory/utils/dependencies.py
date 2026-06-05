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
        
        # Check common Windows paths
        if platform.system() == "Windows":
            common_paths = [
                Path("C:/Program Files (x86)/Nmap/nmap.exe"),
                Path("C:/Program Files/Nmap/nmap.exe"),
            ]
            for p in common_paths:
                if p.exists():
                    return True
        return False

    @staticmethod
    def is_npcap_installed() -> bool:
        """Heuristic check for Npcap/WinPcap on Windows."""
        if platform.system() != "Windows":
            return True  # Assume libpcap on Linux/macOS or check specifically
        
        # Look for Npcap in common locations or registry (simplified check)
        # Often checking for service or driver presence is better
        try:
            # Check if we can run a scapy-like check or just look for the driver
            # For simplicity, we can check if 'nmap --iflist' works without error
            if DependencyChecker.is_nmap_installed():
                return True # If nmap works, usually pcap is there
            return False
        except Exception:
            return False

    @staticmethod
    def get_missing_dependencies() -> list[str]:
        missing = []
        if not DependencyChecker.is_nmap_installed():
            missing.append("Nmap (optional, for OS fingerprinting)")
        return missing
