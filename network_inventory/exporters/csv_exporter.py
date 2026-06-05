from __future__ import annotations

import csv
from pathlib import Path

from network_inventory.models import DeviceRecord, ScanResult


DEVICE_FIELDS = [
    "ip_address",
    "mac_address",
    "vendor",
    "hostname",
    "device_type",
    "open_ports",
    "tls_common_name",
    "tls_issuer",
    "tls_expired",
    "notes",
]


def _device_row(device: DeviceRecord) -> dict[str, str]:
    ports = "; ".join(
        f"{port.port}/{port.service}"
        + (f" version={port.version}" if port.version else "")
        + (f" banner={port.banner}" if port.banner else "")
        for port in device.open_ports
    )
    return {
        "ip_address": device.ip_address,
        "mac_address": device.mac_address or "",
        "vendor": device.vendor or "",
        "hostname": device.hostname or "",
        "device_type": device.device_type,
        "open_ports": ports,
        "tls_common_name": device.tls.common_name if device.tls and device.tls.common_name else "",
        "tls_issuer": device.tls.issuer if device.tls and device.tls.issuer else "",
        "tls_expired": str(device.tls.expired) if device.tls and device.tls.expired is not None else "",
        "notes": "; ".join(device.notes),
    }


def export_csv(result: ScanResult, output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=DEVICE_FIELDS)
        writer.writeheader()
        for device in result.devices:
            writer.writerow(_device_row(device))

