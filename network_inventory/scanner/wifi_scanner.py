from __future__ import annotations

import asyncio
import logging

from network_inventory.models import WifiNetwork


def _frequency_to_channel(freq: int | None) -> int | None:
    if freq is None:
        return None
    if 2412 <= freq <= 2472:
        return (freq - 2407) // 5
    if freq == 2484:
        return 14
    if 5160 <= freq <= 5885:
        return (freq - 5000) // 5
    return None


def _auth_to_encryption(akm: list[int] | None) -> str:
    """Convert pywifi AKM list to human-readable encryption string."""
    if not akm:
        return "Open"
    # pywifi AKM constants: 0=NONE, 1=WPA, 2=PSK, 3=WPA2, 4=PSK2, etc.
    AKM_MAP = {
        0: "Open",
        1: "WPA-EAP",
        2: "WPA-PSK",
        3: "WPA2-EAP",
        4: "WPA2-PSK",
        5: "WPA/WPA2-PSK",
        6: "WPA3-SAE",
        7: "WPA3-OWE",
    }
    labels = [AKM_MAP.get(a, f"AKM-{a}") for a in akm if a != 0]
    if not labels:
        return "Open"
    # Deduplicate and join
    seen: set[str] = set()
    unique: list[str] = []
    for label in labels:
        if label not in seen:
            unique.append(label)
            seen.add(label)
    return "/".join(unique)


async def scan_wifi(logger: logging.Logger, timeout: float = 4.0) -> list[WifiNetwork]:
    try:
        import pywifi
    except ImportError:
        logger.warning("pywifi is not installed; skipping Wi-Fi scan")
        return []

    def _scan() -> list[WifiNetwork]:
        wifi = pywifi.PyWiFi()
        interfaces = wifi.interfaces()
        if not interfaces:
            logger.warning("No Wi-Fi interface found")
            return []
        iface = interfaces[0]
        iface.scan()
        import time

        time.sleep(timeout)

        networks: list[WifiNetwork] = []
        seen_ssids: set[str] = set()
        for result in iface.scan_results():
            ssid: str = result.ssid or ""
            bssid: str | None = getattr(result, "bssid", None)
            freq: int | None = getattr(result, "freq", None)
            signal: int | None = getattr(result, "signal", None)
            try:
                akm: list[int] | None = result.akm
            except AttributeError:
                akm = None
            channel = _frequency_to_channel(freq)
            encryption = _auth_to_encryption(akm)

            # Deduplicate by SSID (keep the one with strongest signal)
            if ssid and ssid in seen_ssids:
                # Replace if stronger signal
                for i, net in enumerate(networks):
                    if (
                        net.ssid == ssid
                        and signal is not None
                        and net.signal is not None
                        and signal > net.signal
                    ):
                        networks[i] = WifiNetwork(
                            ssid=ssid,
                            bssid=bssid,
                            channel=channel,
                            signal=signal,
                            frequency=freq,
                            encryption=encryption,
                        )
                continue
            if ssid:
                seen_ssids.add(ssid)
            networks.append(
                WifiNetwork(
                    ssid=ssid,
                    bssid=bssid,
                    channel=channel,
                    signal=signal,
                    frequency=freq,
                    encryption=encryption,
                )
            )
        return networks

    try:
        return await asyncio.to_thread(_scan)
    except Exception as exc:
        logger.warning("Wi-Fi scan failed: %s", exc)
        return []
