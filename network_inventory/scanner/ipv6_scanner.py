from __future__ import annotations

import asyncio
import logging
import re
import subprocess
import platform

from network_inventory.models import DeviceRecord


async def discover_ipv6_neighbors(
    logger: logging.Logger,
    target_v4: str | None = None,
) -> list[DeviceRecord]:
    """Discover IPv6 neighbors via system Neighbor Cache and active probes.

    Strategi:
      1. Baca ``netsh interface ipv6 show neighbors`` (Windows) atau
         ``ip -6 neigh`` (Linux).
      2. Kirim ICMPv6 echo ke ff02::1 (all-nodes multicast) untuk populasikan cache.
      3. Ambil IPv6 link-local address kita sendiri dari ``ipconfig``.
    """
    devices: dict[str, DeviceRecord] = {}  # keyed by MAC

    # ── 1. Baca system IPv6 neighbor cache ────────────────────────────────
    neigh_cache = await asyncio.to_thread(_read_neighbor_cache, logger)
    for mac, (ipv6, _iface) in neigh_cache.items():
        mac_up = mac.upper()
        if mac_up not in devices:
            devices[mac_up] = DeviceRecord(
                ip_address=_find_v4_for_mac(mac_up, target_v4) or ipv6,
                mac_address=mac_up,
                ipv6_address=ipv6,
            )
        else:
            # Link-local lebih berguna daripada global/unique-local
            existing = devices[mac_up]
            if not existing.ipv6_address:
                existing.ipv6_address = ipv6
            elif not ipv6.startswith("fe80") and existing.ipv6_address.startswith("fe80"):
                existing.ipv6_address = ipv6

    # ── 2. Ambil IPv6 address interface kita ──────────────────────────────
    try:
        output = subprocess.check_output(["ipconfig"], text=True, timeout=5)
        for block in output.split("\r\n\r\n"):
            ipv6_matches = re.findall(
                r"IPv6 Address[ .:]+([\da-f:]+(?:%\d+)?)",
                block, re.IGNORECASE,
            )
            for ipv6 in ipv6_matches:
                # Simpan sebagai catatan, bukan sebagai device
                logger.debug("Our IPv6: %s", ipv6)
    except Exception:
        pass

    # ── 3. Coba populasikan neighbor cache via ping ff02::1 ───────────────
    try:
        result = await asyncio.to_thread(_ping_multicast_ipv6, logger)
        if result:
            # Baca ulang cache
            new_cache = await asyncio.to_thread(_read_neighbor_cache, logger)
            for mac, (ipv6, _iface) in new_cache.items():
                mac_up = mac.upper()
                if mac_up not in devices:
                    devices[mac_up] = DeviceRecord(
                        ip_address=ipv6,
                        mac_address=mac_up,
                        ipv6_address=ipv6,
                    )
    except Exception as exc:
        logger.debug("IPv6 multicast ping failed: %s", exc)

    return list(devices.values())


# ── System Neighbor Cache Reader ──────────────────────────────────────────────

def _read_neighbor_cache(
    logger: logging.Logger,
) -> dict[str, tuple[str, str]]:
    """Return ``{mac: (ipv6, interface)}`` from the system ND cache."""
    result: dict[str, tuple[str, str]] = {}

    if platform.system().lower() == "windows":
        try:
            output = subprocess.check_output(
                ["netsh", "interface", "ipv6", "show", "neighbors"],
                text=True, timeout=5,
            )
        except Exception as exc:
            logger.debug("IPv6 neighbor cache read failed: %s", exc)
            return result

        # Format: interface  ipv6-address  mac  state
        # Example: 12  fe80::1234%12  aa-bb-cc-dd-ee-ff  Reachable
        for line in output.splitlines():
            m = re.search(
                r"\d+\s+"
                r"([\da-f:]+(?:%\d+)?)\s+"            # IPv6 address
                r"([\da-fA-F]{2}[:\-][\da-fA-F]{2}[:\-][\da-fA-F]{2}"
                r"[:\-][\da-fA-F]{2}[:\-][\da-fA-F]{2}[:\-][\da-fA-F]{2}|"
                r"[\da-fA-F]{2}-[\da-fA-F]{2}-[\da-fA-F]{2}"
                r"-[\da-fA-F]{2}-[\da-fA-F]{2}-[\da-fA-F]{2}|"
                r"ff:ff:ff:ff:ff:ff)\s+"
                r"(\S+)",                               # state
                line, re.IGNORECASE,
            )
            if m:
                ipv6 = m.group(1)
                raw_mac = m.group(2)
                state = m.group(3)
                if state.lower() in ("reachable", "stale", "delay", "probe"):
                    mac = raw_mac.replace("-", ":").upper()
                    if mac != "FF:FF:FF:FF:FF:FF":
                        # Extract interface index
                        iface = ipv6.split("%")[-1] if "%" in ipv6 else ""
                        if mac not in result:
                            result[mac] = (ipv6, iface)
    else:
        # Linux: ip -6 neigh
        try:
            output = subprocess.check_output(
                ["ip", "-6", "neigh"], text=True, timeout=5,
            )
            for line in output.splitlines():
                m = re.search(
                    r"([\da-f:]+(?:%\S+)?)\s+dev\s+(\S+)\s+"
                    r"lladdr\s+([\da-fA-F:]{17})\s+(\S+)",
                    line,
                )
                if m:
                    ipv6 = m.group(1)
                    iface = m.group(2)
                    mac = m.group(3).upper()
                    state = m.group(4)
                    if state.lower() in ("reachable", "stale", "delay", "probe"):
                        if mac != "FF:FF:FF:FF:FF:FF" and mac not in result:
                            result[mac] = (ipv6, iface)
        except Exception:
            pass

    return result


# ── IPv6 Multicast Ping ───────────────────────────────────────────────────────

def _ping_multicast_ipv6(logger: logging.Logger) -> bool:
    """Ping ff02::1 to populate the neighbor cache (Windows only)."""
    try:
        if platform.system().lower() == "windows":
            # Find a suitable interface index
            output = subprocess.check_output(
                ["netsh", "interface", "ipv6", "show", "interfaces"],
                text=True, timeout=5,
            )
            # Pick the first non-loopback interface
            iface_idx = None
            for line in output.splitlines():
                m = re.match(r"\s*(\d+)\s+", line)
                if m:
                    idx = m.group(1)
                    if idx != "1":  # skip loopback
                        iface_idx = idx
                        break
            if iface_idx:
                subprocess.check_output(
                    ["ping", "-6", "-n", "1", "-l", "0", "-w", "1000",
                     f"ff02::1%{iface_idx}"],
                    stderr=subprocess.STDOUT, timeout=3,
                )
                return True
        else:
            subprocess.check_output(
                ["ping6", "-c", "1", "-w", "1", "ff02::1"],
                stderr=subprocess.STDOUT, timeout=3,
            )
            return True
    except Exception:
        pass
    return False


# ── Helper: guess IPv4 from MAC ───────────────────────────────────────────────

def _find_v4_for_mac(mac: str, target_v4: str | None) -> str | None:
    """Try to find the IPv4 for a given MAC address from ``arp -a``."""
    if not target_v4:
        return None
    try:
        output = subprocess.check_output(["arp", "-a"], text=True, timeout=5)
        for line in output.splitlines():
            m = re.search(
                r"(\d{1,3}(?:\.\d{1,3}){3})\s+"
                r"([\da-fA-F]{2}[:\-][\da-fA-F]{2}[:\-][\da-fA-F]{2}"
                r"[:\-][\da-fA-F]{2}[:\-][\da-fA-F]{2}[:\-][\da-fA-F]{2})",
                line,
            )
            if m:
                ip = m.group(1)
                cache_mac = m.group(2).replace("-", ":").upper()
                if cache_mac == mac:
                    return ip
    except Exception:
        pass
    return None
