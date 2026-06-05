from __future__ import annotations

import re

from network_inventory.models import PortInfo


VERSION_PATTERNS = [
    re.compile(r"OpenSSH[_/ ](?P<version>[\w.\-]+)", re.IGNORECASE),
    re.compile(r"vsftpd (?P<version>[\w.\-]+)", re.IGNORECASE),
    re.compile(r"Apache/?(?P<version>[\w.\-]+)?", re.IGNORECASE),
    re.compile(r"nginx/?(?P<version>[\w.\-]+)?", re.IGNORECASE),
]


def enrich_service(port_info: PortInfo) -> PortInfo:
    if not port_info.banner:
        return port_info
    for pattern in VERSION_PATTERNS:
        match = pattern.search(port_info.banner)
        if match:
            version = match.groupdict().get("version")
            if version:
                port_info.version = version
            break
    return port_info

