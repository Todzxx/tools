from __future__ import annotations

from network_inventory.models import DeviceRecord, ScanResult
from network_inventory.storage.database import ScanDatabase


class TestScanDatabase:
    def test_create_db_in_memory(self):
        db = ScanDatabase(":memory:")
        db.open()
        assert db._conn is not None
        db.close()

    def test_save_and_get_stats(self, temp_dir):
        db_path = str(temp_dir / "test.db")
        db = ScanDatabase(db_path)
        db.open()

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
        ]
        result.finish()

        db.save_scan(result)

        stats = db.get_stats()
        assert stats is not None
        assert stats["total_devices"] >= 2
        assert stats["device_types"] >= 2

        devices = db.get_all_devices()
        assert len(devices) >= 2

        db.close()

    def test_save_multiple_scans(self, temp_dir):
        db_path = str(temp_dir / "multi.db")
        db = ScanDatabase(db_path)
        db.open()

        for i in range(3):
            result = ScanResult.start(f"10.0.{i}.0/24")
            result.devices = [
                DeviceRecord(
                    ip_address=f"10.0.{i}.1",
                    mac_address=f"AA:BB:CC:DD:EE:0{i}",
                    device_type="Desktop",
                )
            ]
            result.finish()
            db.save_scan(result)

        stats = db.get_stats()
        assert stats is not None
        assert stats["total_devices"] >= 1

        db.close()

    def test_empty_database(self, temp_dir):
        db_path = str(temp_dir / "empty.db")
        db = ScanDatabase(db_path)
        db.open()

        stats = db.get_stats()
        assert stats is None or stats["total_devices"] == 0

        devices = db.get_all_devices()
        assert devices == []

        db.close()

    def test_get_last_scan_id(self, temp_dir):
        db_path = str(temp_dir / "last_scan.db")
        db = ScanDatabase(db_path)
        db.open()

        result = ScanResult.start("192.168.1.0/24")
        result.devices = [DeviceRecord(ip_address="192.168.1.1", device_type="Router")]
        result.finish()
        db.save_scan(result)

        last_id = db.get_last_scan_id()
        assert last_id is not None
        assert isinstance(last_id, str)
        assert len(last_id) > 0

        db.close()

    def test_get_all_devices(self, temp_dir):
        db_path = str(temp_dir / "all_devices.db")
        db = ScanDatabase(db_path)
        db.open()

        result = ScanResult.start("192.168.1.0/24")
        result.devices = [DeviceRecord(ip_address="192.168.1.1", device_type="Router")]
        result.finish()
        db.save_scan(result)

        devices = db.get_all_devices()
        assert len(devices) >= 1

        db.close()
