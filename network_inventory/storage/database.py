from __future__ import annotations

import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from network_inventory.models import ScanResult


SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS scans (
    id          TEXT PRIMARY KEY,
    target      TEXT NOT NULL,
    started_at  TEXT NOT NULL,
    finished_at TEXT,
    device_count INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS devices (
    mac              TEXT PRIMARY KEY,
    first_seen       TEXT NOT NULL,
    last_seen        TEXT NOT NULL,
    last_ip          TEXT,
    last_hostname    TEXT,
    last_vendor      TEXT,
    last_device_type TEXT,
    last_os_family   TEXT,
    last_ipv6        TEXT,
    seen_count       INTEGER DEFAULT 1
);

CREATE TABLE IF NOT EXISTS device_history (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id      TEXT NOT NULL,
    mac          TEXT NOT NULL,
    ip_address   TEXT,
    hostname     TEXT,
    vendor       TEXT,
    device_type  TEXT,
    os_family    TEXT,
    ipv6_address TEXT,
    open_ports   TEXT,
    seen_at      TEXT NOT NULL,
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);

CREATE INDEX IF NOT EXISTS idx_history_mac   ON device_history(mac);
CREATE INDEX IF NOT EXISTS idx_history_scan  ON device_history(scan_id);
CREATE INDEX IF NOT EXISTS idx_devices_last  ON devices(last_seen);
"""


class ScanDatabase:
    """SQLite-backed device history database (mirip Fing)."""

    def __init__(self, db_path: str | Path) -> None:
        self._path = Path(db_path)
        self._conn: sqlite3.Connection | None = None

    def open(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self._path))
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(SCHEMA_SQL)

    def close(self) -> None:
        if self._conn:
            self._conn.commit()
            self._conn.close()
            self._conn = None

    # ── Save scan ─────────────────────────────────────────────────────────

    def save_scan(self, result: ScanResult) -> tuple[str, list[dict[str, Any]]]:
        """Save scan results and return (scan_id, changes).

        *changes* contains one dict per device:
          {"mac": ..., "ip": ..., "action": "new" | "updated" | "ip_changed"}
        """
        if not self._conn:
            self.open()

        scan_id = str(uuid.uuid4())
        changes: list[dict[str, Any]] = []

        # Insert scan record
        self._conn.execute(
            "INSERT OR REPLACE INTO scans (id, target, started_at, finished_at, device_count) "
            "VALUES (?, ?, ?, ?, ?)",
            (scan_id, result.target, result.started_at, result.finished_at, len(result.devices)),
        )

        now = datetime.now(timezone.utc).isoformat(timespec="seconds")

        for device in result.devices:
            mac = (device.mac_address or device.ip_address).upper()
            ports_json = ",".join(f"{p.port}/{p.service}" for p in device.open_ports)

            # Insert history row
            self._conn.execute(
                "INSERT INTO device_history "
                "(scan_id, mac, ip_address, hostname, vendor, device_type, "
                " os_family, ipv6_address, open_ports, seen_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (scan_id, mac, device.ip_address, device.hostname,
                 device.vendor, device.device_type, device.os_family,
                 device.ipv6_address, ports_json, now),
            )

            # Upsert device record
            existing = self._conn.execute(
                "SELECT * FROM devices WHERE mac = ?", (mac,)
            ).fetchone()

            action: str
            if existing is None:
                action = "new"
                self._conn.execute(
                    "INSERT INTO devices "
                    "(mac, first_seen, last_seen, last_ip, last_hostname, "
                    " last_vendor, last_device_type, last_os_family, "
                    " last_ipv6, seen_count) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1)",
                    (mac, now, now, device.ip_address, device.hostname,
                     device.vendor, device.device_type, device.os_family,
                     device.ipv6_address),
                )
            else:
                if existing["last_ip"] != device.ip_address:
                    action = "ip_changed"
                else:
                    action = "updated"
                self._conn.execute(
                    "UPDATE devices SET "
                    "  last_seen=?, last_ip=?, last_hostname=?, last_vendor=?, "
                    "  last_device_type=?, last_os_family=?, last_ipv6=?, "
                    "  seen_count=seen_count+1 "
                    "WHERE mac=?",
                    (now, device.ip_address, device.hostname,
                     device.vendor, device.device_type, device.os_family,
                     device.ipv6_address, mac),
                )

            changes.append({
                "mac": mac,
                "ip": device.ip_address,
                "hostname": device.hostname,
                "action": action,
            })

        self._conn.commit()
        return scan_id, changes

    # ── Query helpers ─────────────────────────────────────────────────────

    def get_device(self, mac: str) -> dict[str, Any] | None:
        if not self._conn:
            return None
        row = self._conn.execute(
            "SELECT * FROM devices WHERE mac = ?", (mac.upper(),)
        ).fetchone()
        return dict(row) if row else None

    def get_history(self, mac: str, limit: int = 20) -> list[dict[str, Any]]:
        if not self._conn:
            return []
        rows = self._conn.execute(
            "SELECT * FROM device_history WHERE mac = ? "
            "ORDER BY seen_at DESC LIMIT ?",
            (mac.upper(), limit),
        ).fetchall()
        return [dict(r) for r in rows]

    def get_all_devices(self) -> list[dict[str, Any]]:
        if not self._conn:
            return []
        rows = self._conn.execute(
            "SELECT * FROM devices ORDER BY last_seen DESC"
        ).fetchall()
        return [dict(r) for r in rows]

    def get_new_since(self, since: str) -> list[dict[str, Any]]:
        """Return devices first_seen after *since* (ISO timestamp)."""
        if not self._conn:
            return []
        rows = self._conn.execute(
            "SELECT * FROM devices WHERE first_seen > ? ORDER BY first_seen DESC",
            (since,),
        ).fetchall()
        return [dict(r) for r in rows]

    def get_stats(self) -> dict[str, Any]:
        if not self._conn:
            return {}
        return dict(self._conn.execute(
            "SELECT "
            "  COUNT(*) AS total_devices, "
            "  COUNT(DISTINCT last_device_type) AS device_types, "
            "  MAX(last_seen) AS last_scan "
            "FROM devices"
        ).fetchone())

    def get_last_scan_id(self) -> str | None:
        if not self._conn:
            return None
        row = self._conn.execute(
            "SELECT id FROM scans ORDER BY started_at DESC LIMIT 1"
        ).fetchone()
        return row["id"] if row else None

    def get_scan_ids(self, limit: int = 10) -> list[dict[str, Any]]:
        if not self._conn:
            return []
        rows = self._conn.execute(
            "SELECT id, target, started_at, finished_at, device_count "
            "FROM scans ORDER BY started_at DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]

    def get_devices_by_scan(self, scan_id: str) -> list[dict[str, Any]]:
        if not self._conn:
            return []
        rows = self._conn.execute(
            "SELECT * FROM device_history WHERE scan_id = ? ORDER BY ip_address",
            (scan_id,),
        ).fetchall()
        return [dict(r) for r in rows]

    def diff_scans(self, scan_a: str, scan_b: str) -> dict[str, list[dict[str, Any]]]:
        if not self._conn:
            return {"new": [], "removed": [], "changed": []}

        def _key(dev: dict[str, Any]) -> str:
            return (dev["mac"] or dev["ip_address"]).upper()

        a_devs = self.get_devices_by_scan(scan_a)
        b_devs = self.get_devices_by_scan(scan_b)

        a_map = {_key(d): d for d in a_devs}
        b_map = {_key(d): d for d in b_devs}

        a_keys = set(a_map)
        b_keys = set(b_map)

        new_devs = [b_map[k] for k in b_keys - a_keys]
        removed_devs = [a_map[k] for k in a_keys - b_keys]

        changed = []
        for k in a_keys & b_keys:
            a = a_map[k]
            b = b_map[k]
            if (
                a.get("ip_address") != b.get("ip_address")
                or a.get("hostname") != b.get("hostname")
                or a.get("device_type") != b.get("device_type")
                or a.get("vendor") != b.get("vendor")
            ):
                changed.append({"before": a, "after": b})

        return {"new": new_devs, "removed": removed_devs, "changed": changed}
