from __future__ import annotations

import asyncio
import logging
import socket


async def query_netbios(ip: str, timeout: float = 0.8) -> str | None:
    """
    Sends a NetBIOS Name Query Request to a specific IP.
    Returns the NetBIOS name if found.
    """
    # NetBIOS Name Service Query Packet (simplified)
    # Transaction ID (2 bytes), Flags (2 bytes), Questions (2 bytes), etc.
    # Standard query for * <00...>
    query = (
        b"\x82\x28\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        b"\x20\x43\x4b\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41"
        b"\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x00"
        b"\x00\x21\x00\x01"
    )

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(query, (ip, 137))

        data, _ = sock.recvfrom(1024)
        if len(data) > 56:
            # NetBIOS name starts at offset 57
            # This is a very simplified parser
            name_len = 15  # Standard NetBIOS name length
            name = data[57 : 57 + name_len].decode("ascii", errors="ignore").strip()
            return name
    except Exception:
        pass
    return None


async def batch_netbios_scan(
    ip_addresses: list[str], logger: logging.Logger, timeout: float = 0.8
) -> dict[str, str]:
    """Scans multiple IPs for NetBIOS names in parallel."""
    results: dict[str, str] = {}
    semaphore = asyncio.Semaphore(100)

    async def _probe(ip: str):
        async with semaphore:
            name = await query_netbios(ip, timeout)
            if name:
                results[ip] = name

    await asyncio.gather(*(_probe(ip) for ip in ip_addresses))
    return results
