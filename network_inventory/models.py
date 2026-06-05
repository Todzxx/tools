from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class PortInfo(BaseModel):
    port: int
    service: str
    open: bool = False
    banner: str | None = None
    version: str | None = None


class TLSCertificateInfo(BaseModel):
    common_name: str | None = None
    issuer: str | None = None
    expires_at: str | None = None
    expired: bool | None = None


class DeviceRecord(BaseModel):
    ip_address: str
    mac_address: str | None = None
    vendor: str | None = None
    hostname: str | None = None
    device_type: str = "Unknown"
    os_family: str | None = None
    ttl: int | None = None
    ipv6_address: str | None = None
    open_ports: list[PortInfo] = Field(default_factory=list)
    tls: TLSCertificateInfo | None = None
    notes: list[str] = Field(default_factory=list)


class SsdpDevice(BaseModel):
    location: str | None
    server: str | None
    st: str | None
    usn: str | None
    manufacturer: str | None = None
    model: str | None = None


class MdnsService(BaseModel):
    name: str
    service_type: str
    addresses: list[str] = Field(default_factory=list)
    port: int | None = None
    server: str | None = None
    properties: dict[str, str] = Field(default_factory=dict)


class WifiNetwork(BaseModel):
    ssid: str
    bssid: str | None
    channel: int | None
    signal: int | None
    frequency: int | None = None
    encryption: str = "Unknown"


class BluetoothDevice(BaseModel):
    name: str | None
    address: str
    rssi: int | None = None


class OnvifDevice(BaseModel):
    endpoint: str
    manufacturer: str | None = None
    model: str | None = None
    firmware_version: str | None = None
    serial_number: str | None = None


class ScanResult(BaseModel):
    target: str
    started_at: str
    finished_at: str | None = None
    devices: list[DeviceRecord] = Field(default_factory=list)
    ssdp_devices: list[SsdpDevice] = Field(default_factory=list)
    mdns_services: list[MdnsService] = Field(default_factory=list)
    wifi_networks: list[WifiNetwork] = Field(default_factory=list)
    bluetooth_devices: list[BluetoothDevice] = Field(default_factory=list)
    onvif_devices: list[OnvifDevice] = Field(default_factory=list)

    @classmethod
    def start(cls, target: str) -> "ScanResult":
        return cls(target=target, started_at=datetime.now().isoformat(timespec="seconds"))

    def finish(self) -> None:
        self.finished_at = datetime.now().isoformat(timespec="seconds")

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump()
