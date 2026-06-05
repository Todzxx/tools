from __future__ import annotations

import asyncio
import re
import socket
import subprocess


async def reverse_dns_lookup(ip_address: str) -> str | None:
    def _lookup() -> str | None:
        try:
            hostname, _, _ = socket.gethostbyaddr(ip_address)
            return hostname.rstrip(".")
        except (socket.herror, socket.gaierror, OSError):
            pass

        # Fallback to NetBIOS (nbtstat -A <ip>)
        try:
            output = subprocess.check_output(
                ["nbtstat", "-A", ip_address], text=True, timeout=2
            )
            # Find the first unique NetBIOS name
            for line in output.splitlines():
                if "<00>" in line and "UNIQUE" in line:
                    match = re.match(r"\s*([^\s]+)\s+<00>", line)
                    if match:
                        return match.group(1)
        except Exception:
            pass
        return None

    return await asyncio.to_thread(_lookup)
