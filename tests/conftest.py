from __future__ import annotations

import logging
from pathlib import Path

import pytest
import yaml

from network_inventory.models import (
    BluetoothDevice,
    DeviceRecord,
    MdnsService,
    OnvifDevice,
    PortInfo,
    ScanResult,
    SsdpDevice,
    TLSCertificateInfo,
    WifiNetwork,
)


@pytest.fixture
def logger():
    return logging.getLogger("test")


@pytest.fixture
def sample_device() -> DeviceRecord:
    return DeviceRecord(
        ip_address="192.168.1.100",
        mac_address="AA:BB:CC:DD:EE:FF",
        vendor="TestVendor",
        hostname="test-device",
        device_type="Desktop",
        os_family="Windows",
        ttl=128,
    )


@pytest.fixture
def sample_port_info() -> PortInfo:
    return PortInfo(
        port=80, service="http", open=True, banner="Apache/2.4.41", version="2.4.41"
    )


@pytest.fixture
def sample_tls_info() -> TLSCertificateInfo:
    return TLSCertificateInfo(
        common_name="example.com",
        issuer="Let's Encrypt",
        expires_at="2026-01-01",
        expired=False,
    )


@pytest.fixture
def sample_scan_result() -> ScanResult:
    result = ScanResult.start("192.168.1.0/24")
    result.devices = [
        DeviceRecord(
            ip_address="192.168.1.1",
            mac_address="11:22:33:44:55:66",
            device_type="Router",
        ),
        DeviceRecord(
            ip_address="192.168.1.100",
            mac_address="AA:BB:CC:DD:EE:FF",
            device_type="Desktop",
        ),
        DeviceRecord(ip_address="192.168.1.101", device_type="Smartphone"),
    ]
    result.finish()
    return result


@pytest.fixture
def sample_ssdp() -> list[SsdpDevice]:
    return [
        SsdpDevice(
            location="http://192.168.1.50:5000/description.xml",
            server="Linux/5.4 UPnP/1.0",
            st="urn:schemas-upnp-org:device:MediaRenderer:1",
            usn="uuid:1234::urn:schemas-upnp-org:device:MediaRenderer:1",
            manufacturer="Samsung",
            model="SmartTV 2024",
        )
    ]


@pytest.fixture
def sample_mdns() -> list[MdnsService]:
    return [
        MdnsService(
            name="Printer HP",
            service_type="_printer._tcp.local.",
            addresses=["192.168.1.200"],
            port=631,
            server="HP-OfficeJet.local.",
        )
    ]


@pytest.fixture
def sample_onvif() -> list[OnvifDevice]:
    return [
        OnvifDevice(
            endpoint="http://192.168.1.50:8080/onvif/device_service",
            manufacturer="Hikvision",
            model="DS-2CD2142FWD",
            firmware_version="V5.5.0",
            serial_number="SN123456",
        )
    ]


@pytest.fixture
def sample_wifi() -> list[WifiNetwork]:
    return [
        WifiNetwork(
            ssid="MyWiFi",
            bssid="AA:BB:CC:11:22:33",
            channel=6,
            signal=-45,
            frequency=2437,
            encryption="WPA2",
        ),
        WifiNetwork(
            ssid="Guest",
            bssid="AA:BB:CC:44:55:66",
            channel=11,
            signal=-60,
            frequency=2462,
            encryption="WPA2",
        ),
    ]


@pytest.fixture
def sample_bluetooth() -> list[BluetoothDevice]:
    return [
        BluetoothDevice(name="Samsung Buds", address="00:11:22:33:44:55", rssi=-55),
        BluetoothDevice(name=None, address="66:77:88:99:00:11", rssi=-70),
    ]


@pytest.fixture
def temp_dir(tmp_path: Path) -> Path:
    return tmp_path


@pytest.fixture
def config_yaml(temp_dir: Path) -> Path:
    cfg = {
        "scanner": {
            "allow_public": False,
            "max_hosts": 1024,
            "timeout": 2.0,
            "use_nmap": False,
            "use_dhcp": False,
            "use_snmp": False,
            "snmp_communities": ["public"],
            "db_path": str(temp_dir / "test.db"),
        },
        "router": {
            "ip": "192.168.1.1",
            "username": "admin",
            "password": "admin",
        },
        "output_dir": str(temp_dir),
    }
    path = temp_dir / "config.yaml"
    with open(path, "w") as f:
        yaml.dump(cfg, f)
    return path
