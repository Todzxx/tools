from __future__ import annotations

import asyncio
import logging

import ipaddress

from zeroconf import ServiceBrowser, Zeroconf
from zeroconf.asyncio import AsyncZeroconf
from network_inventory.models import MdnsService


class ServiceListener:
    def __init__(self, services: list[MdnsService]) -> None:
        self.services = services

    def remove_service(self, zeroconf: Zeroconf, type: str, name: str) -> None:
        pass

    def add_service(self, zeroconf: Zeroconf, type: str, name: str) -> None:
        info = zeroconf.get_service_info(type, name)
        if info:
            addresses = [str(ipaddress.ip_address(addr)) for addr in info.addresses]
            self.services.append(
                MdnsService(
                    name=name,
                    service_type=type,
                    addresses=addresses,
                    port=info.port,
                    server=info.server,
                    properties={str(k): str(v) for k, v in info.properties.items()},
                )
            )

    def update_service(self, zeroconf: Zeroconf, type: str, name: str) -> None:
        pass


# Comprehensive list of service types to find ANY mobile/IoT device
COMMON_SERVICES = [
    "_http._tcp.local.",
    "_https._tcp.local.",
    "_googlecast._tcp.local.",  # Android / Chromecast
    "_apple-mobdev2._tcp.local.",  # iPhone / iPad
    "_airplay._tcp.local.",  # Apple AirPlay
    "_spotify-connect._tcp.local.",  # Spotify Devices
    "_printer._tcp.local.",  # Printers
    "_ipp._tcp.local.",  # AirPrint
    "_smb._tcp.local.",  # Windows/Mac Shares
    "_afpovertcp._tcp.local.",  # Mac Shares
    "_raop._tcp.local.",  # Airport Express
    "_workstation._tcp.local.",  # General Computers
]


async def discover_mdns(
    logger: logging.Logger, timeout: float = 3.0
) -> list[MdnsService]:
    """Discover hosts via mDNS (Zeroconf) aggressively."""
    services: list[MdnsService] = []
    aiozc = AsyncZeroconf()
    listener = ServiceListener(services)

    logger.debug("Starting aggressive mDNS discovery...")

    # Browse for many common service types in parallel
    browsers = [
        ServiceBrowser(aiozc.zeroconf, srv, listener) for srv in COMMON_SERVICES
    ]

    await asyncio.sleep(timeout)

    for b in browsers:
        b.cancel()
    await aiozc.async_close()

    # Deduplicate by name and address
    unique: dict[str, MdnsService] = {}
    for s in services:
        key = f"{s.name}-{s.addresses}"
        if key not in unique:
            unique[key] = s

    return list(unique.values())
