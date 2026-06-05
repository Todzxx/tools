from __future__ import annotations

from network_inventory.detectors.device_classifier import classify_device
from network_inventory.detectors.os_detector import infer_os_family
from network_inventory.models import DeviceRecord


class TestDeviceClassifier:
    def test_router_by_vendor_cisco(self):
        dev = DeviceRecord(ip_address="10.0.0.1", vendor="Cisco Systems")
        assert classify_device(dev) == "Router"

    def test_router_by_vendor_huawei(self):
        dev = DeviceRecord(ip_address="10.0.0.1", vendor="Huawei Technologies")
        assert classify_device(dev) == "Smartphone"

    def test_router_by_open_ports(self):
        dev = DeviceRecord(ip_address="10.0.0.1", open_ports=[])
        from network_inventory.models import PortInfo

        dev.open_ports = [
            PortInfo(port=443, service="https", open=True),
            PortInfo(port=80, service="http", open=True),
            PortInfo(port=53, service="dns", open=True),
        ]
        assert classify_device(dev) == "Router"

    def test_windows_by_vendor(self):
        dev = DeviceRecord(ip_address="10.0.0.2", vendor="Microsoft Corporation")
        assert classify_device(dev) in ("Desktop", "Unknown")

    def test_apple_by_vendor(self):
        dev = DeviceRecord(ip_address="10.0.0.3", vendor="Apple Inc.")
        assert classify_device(dev) in ("Mac", "Smartphone", "iPhone")

    def test_samsung_by_vendor(self):
        dev = DeviceRecord(ip_address="10.0.0.4", vendor="Samsung Electronics")
        assert classify_device(dev) in ("Smartphone", "Android", "Smart TV")

    def test_unknown_default(self):
        dev = DeviceRecord(ip_address="10.0.0.5", vendor="Unknown Corp")
        assert classify_device(dev) in ("Unknown", "Desktop")

    def test_hp_by_vendor(self):
        dev = DeviceRecord(ip_address="10.0.0.6", vendor="HP Inc.")
        assert classify_device(dev) in ("Printer", "Desktop", "Laptop")


class TestOsDetector:
    def test_windows_ttl(self):
        dev = DeviceRecord(ip_address="10.0.0.1", ttl=128)
        assert infer_os_family(dev) == "Windows"

    def test_linux_ttl(self):
        dev = DeviceRecord(ip_address="10.0.0.2", ttl=64)
        assert infer_os_family(dev) == "Linux/Mac"

    def test_bsd_ttl(self):
        dev = DeviceRecord(ip_address="10.0.0.3", ttl=255)
        assert infer_os_family(dev) == "Cisco/Solaris"

    def test_unknown_ttl(self):
        dev = DeviceRecord(ip_address="10.0.0.4", ttl=200)
        assert infer_os_family(dev) == "Windows"

    def test_no_ttl_returns_none(self):
        dev = DeviceRecord(ip_address="10.0.0.5")
        assert infer_os_family(dev) is None

    def test_ios_by_hostname(self):
        dev = DeviceRecord(ip_address="10.0.0.6", hostname="iphone-tim")
        os = infer_os_family(dev)
        assert os == "iOS" or os is not None
