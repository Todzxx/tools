from __future__ import annotations

import os
import platform
import ctypes


class PermissionChecker:
    """Checks for necessary OS-level permissions (e.g., Administrator/Root)."""

    @staticmethod
    def is_admin() -> bool:
        """Returns True if the current user has administrative/root privileges."""
        try:
            if platform.system() == "Windows":
                return ctypes.windll.shell32.IsUserAnAdmin() != 0  # type: ignore[attr-defined]
            else:
                return os.getuid() == 0  # type: ignore[attr-defined]
        except Exception:
            return False

    @staticmethod
    def get_permission_warning() -> str | None:
        if not PermissionChecker.is_admin():
            if platform.system() == "Windows":
                return "Scanning is running without Administrator privileges. Some features (ARP, OS detection) may be limited."
            else:
                return "Scanning is running without root privileges. Try using 'sudo' for better results."
        return None
