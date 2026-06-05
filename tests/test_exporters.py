from __future__ import annotations

import json

from network_inventory.exporters.csv_exporter import export_csv
from network_inventory.exporters.json_exporter import export_json
from network_inventory.exporters.html_exporter import export_html


class TestJsonExporter:
    def test_export_json(self, sample_scan_result, temp_dir):
        path = temp_dir / "test.json"
        export_json(sample_scan_result, path)
        assert path.exists()

        with open(path) as f:
            data = json.load(f)
        assert data["target"] == "192.168.1.0/24"
        assert len(data["devices"]) == 3

    def test_export_json_empty_devices(self, temp_dir):
        from network_inventory.models import ScanResult
        result = ScanResult.start("10.0.0.0/24")
        path = temp_dir / "empty.json"
        export_json(result, path)
        with open(path) as f:
            data = json.load(f)
        assert len(data["devices"]) == 0


class TestCsvExporter:
    def test_export_csv(self, sample_scan_result, temp_dir):
        path = temp_dir / "test.csv"
        export_csv(sample_scan_result, path)
        assert path.exists()

        content = path.read_text(encoding="utf-8")
        assert "192.168.1.1" in content
        assert "Router" in content
        # 1 header + 3 data rows
        assert len(content.strip().splitlines()) == 4

    def test_export_csv_empty(self, temp_dir):
        from network_inventory.models import ScanResult
        result = ScanResult.start("10.0.0.0/24")
        path = temp_dir / "empty.csv"
        export_csv(result, path)
        assert path.exists()
        # Header only
        header = path.read_text(encoding="utf-8").strip().splitlines()[0]
        assert header.startswith("ip_address")
        assert "mac_address" in header


class TestHtmlExporter:
    def test_export_html(self, sample_scan_result, temp_dir):
        path = temp_dir / "test.html"
        export_html(sample_scan_result, path)
        assert path.exists()

        content = path.read_text(encoding="utf-8")
        assert "<!DOCTYPE html>" in content
        assert "192.168.1.0/24" in content
        assert "Router" in content

    def test_export_html_with_extra_data(self, sample_scan_result, sample_wifi, sample_bluetooth, temp_dir):
        sample_scan_result.wifi_networks = sample_wifi
        sample_scan_result.bluetooth_devices = sample_bluetooth
        path = temp_dir / "full.html"
        export_html(sample_scan_result, path)
        content = path.read_text(encoding="utf-8")
        assert "MyWiFi" in content
        assert "Samsung Buds" in content
