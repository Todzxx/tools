from __future__ import annotations

import asyncio
import ipaddress
import logging
import platform
import re
import subprocess

from network_inventory.detectors.vendor_detector import VendorDetector
from network_inventory.models import DeviceRecord


# ── Suppress Scapy's noisy routing warnings on Windows ────────────────────────
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

TCP_SWEEP_PORTS = [
    80,
    443,
    445,
    22,
    135,
    139,
    8080,
    5353,
    5555,
    62078,
    8008,
    8009,
    1900,
    3000,
    5000,
    554,
]


def _arp_entries_from_system(logger: logging.Logger) -> dict[str, str]:
    """Parse system ARP cache via ``arp -a``."""
    cache: dict[str, str] = {}
    try:
        output = subprocess.check_output(["arp", "-a"], text=True, timeout=5)
        for line in output.splitlines():
            m = re.search(
                r"(\d{1,3}(?:\.\d{1,3}){3})\s+([\da-fA-F]{2}[:\-][\da-fA-F]{2}[:\-][\da-fA-F]{2}"
                r"[:\-][\da-fA-F]{2}[:\-][\da-fA-F]{2}[:\-][\da-fA-F]{2})",
                line,
            )
            if m:
                ip = m.group(1)
                mac = m.group(2).replace("-", ":").upper()
                cache[ip] = mac
    except Exception as exc:
        logger.debug("ARP cache read failed: %s", exc)
    return cache


def _system_ping(ip: str, timeout_sec: float = 1.0) -> bool:
    try:
        if platform.system().lower() == "windows":
            args = ["ping", "-n", "1", "-w", str(int(timeout_sec * 1000)), ip]
        else:
            args = ["ping", "-c", "1", "-W", str(int(timeout_sec)), ip]
        out = subprocess.check_output(
            args, stderr=subprocess.STDOUT, timeout=timeout_sec + 0.5
        )
        text = out.decode("utf-8", errors="replace").lower()
        return "ttl=" in text or "time=" in text
    except Exception:
        return False


async def tcp_sweep(
    target: ipaddress.IPv4Network, known_ips: set[str], logger: logging.Logger
) -> set[str]:
    """Quickly probe common ports to find hosts that block ICMP."""
    found = set()
    semaphore = asyncio.Semaphore(100)

    async def check_port(ip: str, port: int):
        async with semaphore:
            if ip in known_ips:
                return
            try:
                _, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port), timeout=0.8
                )
                writer.close()
                await writer.wait_closed()
                found.add(ip)
            except Exception as exc:
                logger.debug("TCP %s:%d failed: %s", ip, port, exc)

    tasks = []
    for host in target.hosts():
        ip = str(host)
        for port in TCP_SWEEP_PORTS[:5]:
            tasks.append(check_port(ip, port))

    await asyncio.gather(*tasks)
    return found


async def arp_scan(
    target: ipaddress.IPv4Network,
    vendor_detector: VendorDetector,
    logger: logging.Logger,
) -> list[DeviceRecord]:
    """
    Advanced ARP discovery using Scapy (L2) with fallback to system ARP.
    """
    found_devices: dict[str, str] = {}  # ip -> mac

    # 1. Attempt Raw Scapy ARP Scan (Most powerful)
    try:
        from scapy.all import ARP, Ether, srp

        logger.debug("Attempting Raw Scapy ARP scan for %s", target)

        # Broadcast ARP request to the entire subnet
        ans, _ = srp(
            Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(target)),
            timeout=2,
            verbose=False,
            inter=0.01,  # Small interval to avoid overwhelming network
        )

        for _, rcv in ans:
            found_devices[rcv.psrc] = rcv.hwsrc.upper()

    except Exception as e:
        logger.warning(
            "Raw ARP scan failed (probably missing Npcap/Permissions): %s", e
        )

    # 2. Fallback/Augment with Ping Sweep + System ARP Cache
    logger.debug("Performing ping sweep to populate system ARP cache...")
    sem = asyncio.Semaphore(128)

    async def probe(ip: str):
        async with sem:
            if _system_ping(ip):
                pass  # Just to populate cache

    await asyncio.gather(*(probe(str(h)) for h in target.hosts()))

    sys_arp = _arp_entries_from_system(logger)
    for ip, mac in sys_arp.items():
        if ipaddress.ip_address(ip) in target:
            if ip not in found_devices:
                found_devices[ip] = mac

    # 3. Create Records
    results = []
    for ip, mac in found_devices.items():
        dev = DeviceRecord(ip_address=ip, mac_address=mac)
        dev.vendor = await vendor_detector.detect(mac)
        results.append(dev)

    return results


async def icmp_ping(ip: str, logger: logging.Logger) -> bool:
    return await asyncio.to_thread(_system_ping, ip)
