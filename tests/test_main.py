from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from network_inventory.main import app

runner = CliRunner()


class TestCliCommands:
    def test_help(self):
        result = runner.invoke(app, ["--help"])
        assert result.exit_code == 0
        assert "Network Inventory" in result.stdout

    def test_scan_help(self):
        result = runner.invoke(app, ["scan", "--help"])
        assert result.exit_code == 0
        assert "TARGET" in result.stdout
        assert "-nmap" in result.stdout
        assert "-html" in result.stdout

    def test_init_config_default(self, tmp_path):
        orig = Path("config.yaml")
        was_present = orig.exists()

        result = runner.invoke(app, ["init-config"], input="y\n")
        assert result.exit_code == 0
        assert Path("config.yaml").exists()

        if not was_present:
            Path("config.yaml").unlink(missing_ok=True)

    def test_history_no_data(self):
        result = runner.invoke(app, ["history", "--db-path", ":memory:"])
        assert result.exit_code == 0
        assert "No history" in result.stdout

    def test_export_no_data(self):
        result = runner.invoke(app, ["export", "--db-path", ":memory:"])
        assert result.exit_code == 0

    def test_map_no_data(self):
        result = runner.invoke(app, ["map", "--db-path", ":memory:"])
        assert result.exit_code == 0
        assert "No scans found" in result.stdout
