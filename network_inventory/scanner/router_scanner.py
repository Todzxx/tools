from __future__ import annotations

import logging
import re
from typing import Any

from network_inventory.models import DeviceRecord


async def scrape_dhcp_leases(
    gateway_ip: str,
    logger: logging.Logger,
    username: str = "admin",
    password: str = "admin",
) -> list[DeviceRecord]:
    """Scrape DHCP client list from router via HTTP or SNMP.

    Strategi:
      1. SNMP walk .1.3.6.1.2.1.4.22.1.2 (ipNetToMediaPhysAddress)
      2. HTTP/HTTPS scrape (legacy URLs, form login, JSON API)
    """
    devices: list[DeviceRecord] = []
    seen_ips: set[str] = set()

    def _add(ip: str, mac: str, hostname: str | None = None) -> None:
        if ip in seen_ips:
            return
        seen_ips.add(ip)
        mac = mac.replace("-", ":").upper() if mac else mac
        devices.append(DeviceRecord(ip_address=ip, mac_address=mac, hostname=hostname))

    # ── 1. SNMP ────────────────────────────────────────────────────────────
    try:
        import asyncio

        def _snmp_arp() -> list[tuple[str, str, str | None]]:
            try:
                from pysnmp.hlapi import (  # type: ignore[import]
                    CommunityData,
                    ContextData,
                    ObjectType,
                    ObjectIdentity,
                    UdpTransportTarget,
                    bulkCmd,
                )
            except ImportError:
                return []
            results: list[tuple[str, str, str | None]] = []
            try:
                iterator = bulkCmd(
                    CommunityData("public"),
                    UdpTransportTarget((gateway_ip, 161), timeout=2, retries=1),
                    ContextData(),
                    0,
                    50,
                    ObjectType(ObjectIdentity("1.3.6.1.2.1.4.22.1.2")),
                    lookupMib=False,
                )
                for error_indication, _, _, var_binds in iterator:
                    if error_indication:
                        break
                    for var_bind in var_binds:
                        oid = str(var_bind[0])
                        mac_hex = str(var_bind[1])
                        parts = oid.split(".")
                        if len(parts) >= 3:
                            ip = ".".join(parts[-4:])
                            mac = ":".join(
                                format(int(x, 16), "02x") for x in mac_hex.split(":")
                            )
                            results.append((ip, mac.upper(), None))
            except Exception as exc:
                logger.debug("SNMP ARP walk failed: %s", exc)
            return results

        snmp_results = await asyncio.to_thread(_snmp_arp)
        for ip, mac, hn in snmp_results:
            _add(ip, mac, hn)
        if snmp_results:
            logger.debug("SNMP ARP: %d entries", len(snmp_results))
    except ImportError:
        pass

    if devices:
        return devices

    try:
        import requests
    except ImportError:
        return devices

    import urllib3

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    session = requests.Session()
    session.verify = False
    session.headers.update({"User-Agent": "Mozilla/5.0"})

    def _flush(
        parsed: list[tuple[str, str, str | None]], label: str, source: str
    ) -> list[DeviceRecord]:
        for ip, mac, hn in parsed:
            _add(ip, mac, hn)
        logger.debug("%s %s → %d", label, source, len(parsed))
        return devices

    for protocol in ("https", "http"):
        base = f"{protocol}://{gateway_ip}"

        # ── 2a. TP-Link legacy URLs ────────────────────────────────────────
        legacy_urls = [
            f"{base}/userRpm/AssignedIpAddrList.htm",
            f"{base}/userRpm/AssignedIpAddrListRpm.htm",
            f"{base}/wlanAccess.htm",
            f"{base}/dhcp.html",
            f"{base}/status.htm",
            f"{base}/DeviceList.htm",
            f"{base}/Main_Login.htm",
        ]
        for url in legacy_urls:
            try:
                resp = session.get(url, timeout=3, auth=(username, password))
                if resp.status_code == 200 and resp.text:
                    parsed = _parse_html_table(resp.text)
                    if parsed:
                        return _flush(parsed, "TP-Link legacy", url)
            except Exception as exc:
                logger.debug("HTTP legacy URL %s failed: %s", url, exc)

        # ── 2b. TP-Link form login ──────────────────────────────────────────
        try:
            login_url = f"{base}/cgi-bin/luci/"
            session.get(login_url, timeout=3)
            login_payloads = [
                {"username": username, "password": password},
                {"user": username, "pass": password},
                {"username": username, "password": password, "crypt": ""},
            ]
            for payload in login_payloads:
                try:
                    login_resp = session.post(
                        login_url,
                        data=payload,
                        timeout=3,
                        allow_redirects=True,
                    )
                    if login_resp.ok:
                        for du in [
                            f"{base}/cgi-bin/luci/admin/status/leases",
                            f"{base}/cgi-bin/luci/admin/network/dhcp",
                            f"{base}/cgi-bin/luci/admin/status/device",
                        ]:
                            try:
                                resp = session.get(du, timeout=3)
                                if resp.status_code == 200:
                                    parsed = _parse_html_table(resp.text)
                                    if not parsed:
                                        parsed = _parse_json_list(resp.text)
                                    if parsed:
                                        return _flush(parsed, "TP-Link new", du)
                            except Exception as exc:
                                logger.debug("LuCI data URL %s failed: %s", du, exc)
                        break
                except Exception as exc:
                    logger.debug("LuCI login failed: %s", exc)
        except Exception as exc:
            logger.debug("LuCI section failed: %s", exc)

        # ── 2c. OpenWrt / LuCI ─────────────────────────────────────────────
        for url in (
            f"{base}/cgi-bin/luci/admin/status/leases",
            f"{base}/cgi-bin/luci/admin/network/dhcp",
        ):
            try:
                resp = session.get(url, timeout=3, auth=(username, password))
                if resp.status_code == 200:
                    parsed = _parse_html_table(resp.text)
                    if parsed:
                        return _flush(parsed, "OpenWrt", url)
            except Exception as exc:
                logger.debug("OpenWrt %s failed: %s", url, exc)

        # ── 2d. Huawei / ZTE JSON API ──────────────────────────────────────
        for url in (
            f"{base}/api/dhcp/servers",
            f"{base}/api/device/list",
        ):
            try:
                resp = session.get(url, timeout=3, auth=(username, password))
                if resp.status_code == 200:
                    parsed = _parse_json_list(resp.text)
                    if parsed:
                        return _flush(parsed, "JSON API", url)
            except Exception as exc:
                logger.debug("JSON API %s failed: %s", url, exc)

    return devices


# ── Parsers ───────────────────────────────────────────────────────────────────


def _parse_html_table(html: str) -> list[tuple[str, str, str | None]]:
    results: list[tuple[str, str, str | None]] = []

    rows = re.findall(
        r"<tr[^>]*>" + r"(?:.*?)<td[^>]*>(\d{1,3}(?:\.\d{1,3}){3})</td>"
        r"\s*<td[^>]*>([\da-fA-F:.-]{10,})</td>"
        r"\s*<td[^>]*>([^<]*)</td>",
        html,
        re.IGNORECASE | re.DOTALL,
    )
    for ip, mac, hostname in rows:
        results.append((ip, mac, hostname.strip() or None))
    if results:
        return results

    lines = re.findall(
        r"(\d{1,3}(?:\.\d{1,3}){3})\s+"
        r"([\da-fA-F]{2}[:-][\da-fA-F]{2}[:-][\da-fA-F]{2}[:-][\da-fA-F]{2}"
        r"[:-][\da-fA-F]{2}[:-][\da-fA-F]{2})"
        r"(?:\s+([^\s<\"']+))?",
        html,
    )
    for ip, mac, hostname in lines:
        results.append((ip, mac, hostname.strip() if hostname else None))
    return results


def _parse_json_list(text: str) -> list[tuple[str, str, str | None]]:
    import json

    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return []

    results: list[tuple[str, str, str | None]] = []

    def _extract(obj: Any) -> None:
        if isinstance(obj, dict):
            ip = obj.get("ipAddress") or obj.get("ip") or obj.get("IPAddress") or ""
            mac = obj.get("macAddress") or obj.get("mac") or obj.get("MACAddress") or ""
            hn = obj.get("hostName") or obj.get("hostname") or obj.get("name") or ""
            if ip and mac:
                results.append((ip, mac, hn or None))
            for val in obj.values():
                _extract(val)
        elif isinstance(obj, list):
            for item in obj:
                _extract(item)

    _extract(data)
    return results
