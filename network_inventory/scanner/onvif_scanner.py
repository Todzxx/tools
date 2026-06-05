from __future__ import annotations

import asyncio
import logging
import socket
import uuid
import xml.etree.ElementTree as ET
from urllib.parse import urlparse

from network_inventory.models import OnvifDevice


ONVIF_MULTICAST = ("239.255.255.250", 3702)


def _probe_message() -> bytes:
    message_id = uuid.uuid4()
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<e:Envelope xmlns:e="http://www.w3.org/2003/05/soap-envelope"
 xmlns:w="http://schemas.xmlsoap.org/ws/2004/08/addressing"
 xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery"
 xmlns:dn="http://www.onvif.org/ver10/network/wsdl">
  <e:Header>
    <w:MessageID>uuid:{message_id}</w:MessageID>
    <w:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</w:To>
    <w:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</w:Action>
  </e:Header>
  <e:Body>
    <d:Probe><d:Types>dn:NetworkVideoTransmitter</d:Types></d:Probe>
  </e:Body>
</e:Envelope>""".encode()


def _extract_xaddrs(payload: bytes) -> list[str]:
    try:
        root = ET.fromstring(payload)
    except ET.ParseError:
        return []
    xaddrs: list[str] = []
    for element in root.iter():
        if element.tag.endswith("XAddrs") and element.text:
            xaddrs.extend(element.text.split())
    return xaddrs


async def discover_onvif(logger: logging.Logger, timeout: float = 4.0) -> list[OnvifDevice]:
    def _discover_endpoints() -> list[str]:
        endpoints: set[str] = set()
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP) as sock:
            sock.settimeout(timeout)
            sock.sendto(_probe_message(), ONVIF_MULTICAST)
            while True:
                try:
                    payload, _ = sock.recvfrom(8192)
                except socket.timeout:
                    break
                endpoints.update(_extract_xaddrs(payload))
        return sorted(endpoints)

    try:
        endpoints = await asyncio.to_thread(_discover_endpoints)
    except OSError as exc:
        logger.warning("ONVIF discovery failed: %s", exc)
        return []

    devices: list[OnvifDevice] = []
    for endpoint in endpoints:
        parsed = urlparse(endpoint)
        devices.append(OnvifDevice(endpoint=endpoint, manufacturer=parsed.hostname, model="ONVIF camera"))
    return devices

