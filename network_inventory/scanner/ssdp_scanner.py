from __future__ import annotations

import asyncio
import logging
import socket
import xml.etree.ElementTree as ET
from urllib.parse import urlparse

from network_inventory.models import SsdpDevice


SSDP_ADDR = ("239.255.255.250", 1900)
M_SEARCH = "\r\n".join(
    [
        "M-SEARCH * HTTP/1.1",
        "HOST: 239.255.255.250:1900",
        'MAN: "ssdp:discover"',
        "MX: 2",
        "ST: ssdp:all",
        "",
        "",
    ]
).encode()


def _parse_headers(payload: bytes) -> dict[str, str]:
    headers: dict[str, str] = {}
    for line in payload.decode("utf-8", errors="ignore").splitlines():
        if ":" in line:
            key, value = line.split(":", 1)
            headers[key.strip().upper()] = value.strip()
    return headers


def _fetch_device_description(
    location: str, timeout: float
) -> tuple[str | None, str | None]:
    parsed = urlparse(location)
    if parsed.scheme not in {"http", "https"}:
        return None, None
    try:
        import requests

        response = requests.get(location, timeout=timeout)
        response.raise_for_status()
        root = ET.fromstring(response.content)
    except ImportError:
        return None, None
    except Exception:
        return None, None

    def find_text(name: str) -> str | None:
        for element in root.iter():
            if element.tag.lower().endswith(name.lower()) and element.text:
                return element.text.strip()
        return None

    return find_text("manufacturer"), find_text("modelName")


async def discover_ssdp(
    logger: logging.Logger, timeout: float = 3.0
) -> list[SsdpDevice]:
    def _discover() -> list[SsdpDevice]:
        devices: list[SsdpDevice] = []
        with socket.socket(
            socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP
        ) as sock:
            sock.settimeout(timeout)
            sock.sendto(M_SEARCH, SSDP_ADDR)
            while True:
                try:
                    payload, _ = sock.recvfrom(4096)
                except socket.timeout:
                    break
                headers = _parse_headers(payload)
                location = headers.get("LOCATION")
                manufacturer, model = (None, None)
                if location:
                    manufacturer, model = _fetch_device_description(
                        location, timeout=1.5
                    )
                devices.append(
                    SsdpDevice(
                        location=location,
                        server=headers.get("SERVER"),
                        st=headers.get("ST"),
                        usn=headers.get("USN"),
                        manufacturer=manufacturer,
                        model=model,
                    )
                )
        return devices

    try:
        return await asyncio.to_thread(_discover)
    except OSError as exc:
        logger.warning("SSDP discovery failed: %s", exc)
        return []
