from __future__ import annotations

from network_inventory.models import (
    BluetoothDevice, DeviceRecord, MdnsService, OnvifDevice,
    PortInfo, ScanResult, SsdpDevice, TLSCertificateInfo, WifiNetwork,
)


class TestDeviceRecord:
    def test_create_minimal(self):
        dev = DeviceRecord(ip_address="192.168.1.1")
        assert dev.ip_address == "192.168.1.1"
        assert dev.device_type == "Unknown"
        assert dev.open_ports == []
        assert dev.notes == []

    def test_create_full(self, sample_device):
        assert sample_device.ip_address == "192.168.1.100"
        assert sample_device.mac_address == "AA:BB:CC:DD:EE:FF"
        assert sample_device.vendor == "TestVendor"
        assert sample_device.hostname == "test-device"
        assert sample_device.device_type == "Desktop"
        assert sample_device.os_family == "Windows"

    def test_with_ports(self):
        dev = DeviceRecord(
            ip_address="10.0.0.1",
            open_ports=[
                PortInfo(port=22, service="ssh"),
                PortInfo(port=80, service="http", banner="Apache"),
            ],
        )
        assert len(dev.open_ports) == 2
        assert dev.open_ports[0].port == 22
        assert dev.open_ports[1].banner == "Apache"

    def test_with_tls(self):
        tls = TLSCertificateInfo(common_name="test.local", expired=False)
        dev = DeviceRecord(ip_address="10.0.0.1", tls=tls)
        assert dev.tls is not None
        assert dev.tls.common_name == "test.local"
        assert dev.tls.expired is False


class TestScanResult:
    def test_start_sets_started_at(self):
        result = ScanResult.start("10.0.0.0/24")
        assert result.target == "10.0.0.0/24"
        assert result.started_at is not None
        assert result.finished_at is None

    def test_finish_sets_finished_at(self):
        result = ScanResult.start("10.0.0.0/24")
        assert result.finished_at is None
        result.finish()
        assert result.finished_at is not None

    def test_to_dict(self):
        result = ScanResult.start("10.0.0.0/24")
        result.devices.append(DeviceRecord(ip_address="10.0.0.1"))
        d = result.to_dict()
        assert d["target"] == "10.0.0.0/24"
        assert len(d["devices"]) == 1

    def test_scan_result_collections(self, sample_scan_result):
        sr = sample_scan_result
        assert len(sr.devices) == 3
        assert sr.devices[0].device_type == "Router"


class TestPortInfo:
    def test_minimal(self):
        p = PortInfo(port=443, service="https")
        assert p.port == 443
        assert p.service == "https"
        assert p.open is False
        assert p.banner is None

    def test_with_all_fields(self, sample_port_info):
        assert sample_port_info.port == 80
        assert sample_port_info.version == "2.4.41"


class TestWifiNetwork:
    def test_minimal(self):
        w = WifiNetwork(ssid="Test", bssid="00:11:22:33:44:55", channel=1, signal=-50)
        assert w.ssid == "Test"
        assert w.encryption == "Unknown"

    def test_from_fixture(self, sample_wifi):
        assert len(sample_wifi) == 2
        assert sample_wifi[0].ssid == "MyWiFi"
        assert sample_wifi[0].encryption == "WPA2"


class TestBluetoothDevice:
    def test_from_fixture(self, sample_bluetooth):
        assert len(sample_bluetooth) == 2
        assert sample_bluetooth[0].name == "Samsung Buds"
        assert sample_bluetooth[1].name is None

    def test_address_required(self):
        bt = BluetoothDevice(address="11:22:33:44:55:66", name="Test")
        assert bt.address == "11:22:33:44:55:66"
        assert bt.name == "Test"


class TestSsdpDevice:
    def test_from_fixture(self, sample_ssdp):
        sd = sample_ssdp[0]
        assert sd.manufacturer == "Samsung"
        assert sd.model == "SmartTV 2024"
        assert sd.location == "http://192.168.1.50:5000/description.xml"

    def test_minimal(self):
        sd = SsdpDevice(location="http://10.0.0.1/desc.xml", server="Linux", st="test", usn="uuid:1")
        assert sd.server == "Linux"


class TestMdnsService:
    def test_from_fixture(self, sample_mdns):
        mdns = sample_mdns[0]
        assert mdns.name == "Printer HP"
        assert mdns.service_type == "_printer._tcp.local."
        assert "192.168.1.200" in mdns.addresses

    def test_with_properties(self):
        mdns = MdnsService(
            name="Test",
            service_type="_http._tcp.local.",
            addresses=["10.0.0.1"],
            properties={"path": "/index.html"},
        )
        assert mdns.properties["path"] == "/index.html"


class TestOnvifDevice:
    def test_from_fixture(self, sample_onvif):
        onvif = sample_onvif[0]
        assert onvif.manufacturer == "Hikvision"
        assert onvif.firmware_version == "V5.5.0"

    def test_minimal(self):
        onvif = OnvifDevice(endpoint="http://10.0.0.1/onvif/service")
        assert onvif.endpoint == "http://10.0.0.1/onvif/service"
        assert onvif.manufacturer is None
