from __future__ import annotations

import asyncio
import ipaddress
import logging
import shutil
from pathlib import Path
import platform

from network_inventory.models import DeviceRecord


def _get_nmap_path() -> str | None:
    if shutil.which("nmap"):
        return "nmap"
    if platform.system() == "Windows":
        for p in [Path("C:/Program Files (x86)/Nmap/nmap.exe"), Path("C:/Program Files/Nmap/nmap.exe")]:
            if p.exists():
                return str(p)
    return None


async def discover_hosts(
    target: ipaddress.IPv4Network,
    logger: logging.Logger,
    timeout: float = 15.0,
) -> list[DeviceRecord]:
    """
    Advanced Nmap discovery using multiple probe types:
    -PE: ICMP Echo
    -PS443: TCP SYN to 443
    -PA80: TCP ACK to 80
    -PP: ICMP Timestamp
    """
    try:
        import nmap
    except ImportError:
        return []
    
    nmap_path = _get_nmap_path()
    if not nmap_path:
        return []

    def _scan() -> list[DeviceRecord]:
        scanner = nmap.PortScanner(nmap_binary=nmap_path)
        # Sangat agresif: Mencoba berbagai jenis 'ping' untuk menembus firewall
        args = f"-sn -PE -PS443 -PA80 -PP --osscan-guess --host-timeout {int(timeout * 1000)}ms"
        
        logger.info("Nmap is probing the network with aggressive flags...")
        scanner.scan(hosts=str(target), arguments=args)
        
        devices: list[DeviceRecord] = []
        for host_ip in scanner.all_hosts():
            host_data = scanner[host_ip]
            if host_data.state() != "up":
                continue
            
            addr = host_data.get("addresses", {})
            mac = addr.get("mac", None)
            vendor = host_data.get("vendor", {}).get(mac or "", None) if mac else None

            hostname = None
            hostnames = host_data.get("hostnames", [])
            if hostnames:
                hostname = hostnames[0].get("name") or None

            os_family = None
            osmatches = host_data.get("osmatch", [])
            if osmatches:
                os_family = osmatches[0].get("name", None)

            devices.append(DeviceRecord(
                ip_address=host_ip,
                mac_address=mac.upper() if mac else None,
                vendor=vendor,
                hostname=hostname,
                os_family=os_family,
            ))
        return devices

    try:
        return await asyncio.to_thread(_scan)
    except Exception as exc:
        logger.debug("Nmap host discovery failed: %s", exc)
        return []
