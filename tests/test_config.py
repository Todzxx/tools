from __future__ import annotations

from pathlib import Path

from network_inventory.utils.config import (
    AppConfig,
    ConfigManager,
    RouterConfig,
    ScannerConfig,
)


class TestAppConfig:
    def test_default_values(self):
        cfg = AppConfig()
        assert cfg.output_dir == "results"
        assert isinstance(cfg.scanner, ScannerConfig)
        assert isinstance(cfg.router, RouterConfig)

    def test_default_scanner(self):
        s = ScannerConfig()
        assert s.allow_public is False
        assert s.max_hosts == 1024
        assert s.use_nmap is False
        assert s.snmp_communities == ["public", "private"]

    def test_default_router(self):
        r = RouterConfig()
        assert r.ip is None
        assert r.username == "admin"
        assert r.password == "admin"

    def test_custom_config(self):
        cfg = AppConfig(
            output_dir="/tmp/scan",
            scanner=ScannerConfig(max_hosts=512, use_nmap=True),
            router=RouterConfig(ip="10.0.0.1", username="user", password="pass"),
        )
        assert cfg.output_dir == "/tmp/scan"
        assert cfg.scanner.max_hosts == 512
        assert cfg.scanner.use_nmap is True
        assert cfg.router.ip == "10.0.0.1"


class TestConfigManager:
    def test_load_default_when_no_file(self, temp_dir):
        path = temp_dir / "nonexistent.yaml"
        mgr = ConfigManager(path)
        cfg = mgr.load()
        assert isinstance(cfg, AppConfig)
        assert cfg.output_dir == "results"

    def test_save_and_load(self, config_yaml: Path):
        mgr = ConfigManager(config_yaml)
        cfg = mgr.load()
        assert cfg.scanner.max_hosts == 1024
        assert cfg.router.ip == "192.168.1.1"
        assert cfg.router.username == "admin"

    def test_save_roundtrip(self, temp_dir):
        path = temp_dir / "roundtrip.yaml"
        original = AppConfig(
            scanner=ScannerConfig(max_hosts=256, use_snmp=True),
            router=RouterConfig(ip="10.0.0.254", username="root", password="secret"),
            output_dir="/tmp/output",
        )
        mgr = ConfigManager(path)
        mgr.save(original)

        loaded = ConfigManager(path).load()
        assert loaded.scanner.max_hosts == 256
        assert loaded.scanner.use_snmp is True
        assert loaded.router.username == "root"
        assert loaded.output_dir == "/tmp/output"

    def test_get_default_path(self):
        path = ConfigManager.get_default_path()
        assert str(path) == "config.yaml"
