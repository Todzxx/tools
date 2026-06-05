from __future__ import annotations

import asyncio
import logging
import re

from network_inventory.models import DeviceRecord, PortInfo


# ── TTL-based OS fingerprints ──────────────────────────────────────────────────
# TTL values are the *initial* TTL set by the OS. We observe the remaining TTL
# after a hop, so we round up to the nearest common initial value.
TTL_FINGERPRINTS: list[tuple[int, str, str]] = [
    (255, "Cisco IOS / Solaris", "Cisco/Solaris"),
    (128, "Windows (NT/2000/XP/7+)", "Windows"),
    (64, "Linux / macOS / *BSD", "Linux/Mac"),
    (60, "Linux (some distros)", "Linux"),
    (32, "Windows (Win95/98/Me)", "Windows (Legacy)"),
]

_TTL_INITIAL_CANDIDATES = [
    255,
    254,
    253,
    252,
    251,
    250,
    128,
    127,
    126,
    125,
    124,
    123,
    122,
    121,
    120,
    64,
    63,
    62,
    61,
    60,
    59,
    58,
    57,
    56,
    55,
    32,
    31,
    30,
]


def _ttl_to_os(ttl: int) -> tuple[str, str] | None:
    """Return (description, short_label) for a given observed TTL."""
    for initial, desc, label in TTL_FINGERPRINTS:
        margin = initial * 0.2
        # Accept TTL within 20% below the initial value (accounting for hops)
        if initial - margin <= ttl <= initial:
            return desc, label
    # Broader fallback ranges
    if ttl >= 250:
        return "Cisco IOS / Solaris", "Cisco/Solaris"
    if ttl >= 120:
        return "Windows NT+", "Windows"
    if ttl >= 55:
        return "Linux / macOS / *BSD", "Linux/Mac"
    if ttl >= 25:
        return "Windows (Legacy)", "Windows (Legacy)"
    return None


# ── Banner-based OS fingerprints ───────────────────────────────────────────────
_BANNER_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (
        re.compile(r"SSH-2\.0-OpenSSH_[\d.]+[_-]?(ubuntu|debian)", re.IGNORECASE),
        "Linux (Ubuntu/Debian)",
    ),
    (re.compile(r"SSH-2\.0-OpenSSH_[\d.]+[_-]?(freebsd)", re.IGNORECASE), "FreeBSD"),
    (re.compile(r"SSH-2\.0-OpenSSH_[\d.]+", re.IGNORECASE), "Linux/Unix (OpenSSH)"),
    (
        re.compile(r"SSH-2\.0-OpenSSH_for_Windows_[\d.]+", re.IGNORECASE),
        "Windows (OpenSSH)",
    ),
    (re.compile(r"SSH-2\.0-dropbear", re.IGNORECASE), "Linux (Dropbear)"),
    (re.compile(r"SSH-2\.0-Cisco", re.IGNORECASE), "Cisco IOS"),
    (re.compile(r"Apache/2\.4\.\d+ \(Ubuntu\)", re.IGNORECASE), "Linux (Ubuntu)"),
    (re.compile(r"Apache/2\.4\.\d+ \(Debian\)", re.IGNORECASE), "Linux (Debian)"),
    (re.compile(r"Apache/2\.4\.\d+ \(CentOS\)", re.IGNORECASE), "Linux (CentOS)"),
    (re.compile(r"Apache/2\.4\.\d+ \(Red Hat", re.IGNORECASE), "Linux (RHEL)"),
    (re.compile(r"Apache/2\.4\.\d+ \(Win", re.IGNORECASE), "Windows"),
    (re.compile(r"nginx/[\d.]+", re.IGNORECASE), "Linux/Unix (nginx)"),
    (re.compile(r"Microsoft-IIS/[\d.]+", re.IGNORECASE), "Windows (IIS)"),
    (re.compile(r"Microsoft FTP", re.IGNORECASE), "Windows"),
    (re.compile(r"vsftpd", re.IGNORECASE), "Linux (vsftpd)"),
    (re.compile(r"proftpd", re.IGNORECASE), "Linux/Unix (ProFTPD)"),
    (re.compile(r"FileZilla", re.IGNORECASE), "Windows"),
    (re.compile(r"Darwin/[\d.]+", re.IGNORECASE), "macOS (Darwin)"),
]

# Keyword-based (from hostname, vendor, notes) is already in infer_os_family
_TEXT_OS_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\bwindows\b", re.IGNORECASE), "Windows"),
    (re.compile(r"\bmicrosoft\b", re.IGNORECASE), "Windows"),
    (re.compile(r"\bwin10\b", re.IGNORECASE), "Windows"),
    (re.compile(r"\bwin11\b", re.IGNORECASE), "Windows"),
    (re.compile(r"\bwin7\b", re.IGNORECASE), "Windows (Legacy)"),
    (re.compile(r"\bwinxp\b", re.IGNORECASE), "Windows (Legacy)"),
    (re.compile(r"\bwin2008\b", re.IGNORECASE), "Windows Server 2008"),
    (re.compile(r"\bwin2012\b", re.IGNORECASE), "Windows Server 2012"),
    (re.compile(r"\bwin2016\b", re.IGNORECASE), "Windows Server 2016"),
    (re.compile(r"\bwin2019\b", re.IGNORECASE), "Windows Server 2019"),
    (re.compile(r"\bwin2022\b", re.IGNORECASE), "Windows Server 2022"),
    (re.compile(r"\blinux\b", re.IGNORECASE), "Linux"),
    (re.compile(r"\bubuntu\b", re.IGNORECASE), "Linux (Ubuntu)"),
    (re.compile(r"\bdebian\b", re.IGNORECASE), "Linux (Debian)"),
    (re.compile(r"\bcentos\b", re.IGNORECASE), "Linux (CentOS)"),
    (re.compile(r"\bred hat\b", re.IGNORECASE), "Linux (RHEL)"),
    (re.compile(r"\bfedora\b", re.IGNORECASE), "Linux (Fedora)"),
    (re.compile(r"\barch\b", re.IGNORECASE), "Linux (Arch)"),
    (re.compile(r"\bopensuse\b", re.IGNORECASE), "Linux (openSUSE)"),
    (re.compile(r"\balpine\b", re.IGNORECASE), "Linux (Alpine)"),
    (re.compile(r"\brapsberry\b", re.IGNORECASE), "Linux (Raspbian)"),
    (re.compile(r"\bpi-\b", re.IGNORECASE), "Linux (Raspbian)"),
    (re.compile(r"\bmacos\b", re.IGNORECASE), "macOS"),
    (re.compile(r"\bmac os\b", re.IGNORECASE), "macOS"),
    (re.compile(r"\bosx\b", re.IGNORECASE), "macOS"),
    (re.compile(r"\bdarwin\b", re.IGNORECASE), "macOS"),
    (re.compile(r"\bimac\b", re.IGNORECASE), "macOS"),
    (re.compile(r"\bmacbook\b", re.IGNORECASE), "macOS"),
    (re.compile(r"\bmacmini\b", re.IGNORECASE), "macOS"),
    (re.compile(r"\biphone\b", re.IGNORECASE), "iOS"),
    (re.compile(r"\bipad\b", re.IGNORECASE), "iPadOS"),
    (re.compile(r"\bapple tv\b", re.IGNORECASE), "tvOS"),
    (re.compile(r"\bandroid\b", re.IGNORECASE), "Android"),
    (re.compile(r"\bsamsung\b", re.IGNORECASE), "Android"),
    (re.compile(r"\bxiaomi\b", re.IGNORECASE), "Android"),
    (re.compile(r"\bgoogle pixel\b", re.IGNORECASE), "Android"),
    (re.compile(r"\bchromecast\b", re.IGNORECASE), "Google Cast"),
    (re.compile(r"\bchrome.?os\b", re.IGNORECASE), "ChromeOS"),
    (re.compile(r"\bcros\b", re.IGNORECASE), "ChromeOS"),
    (re.compile(r"\brouter\b", re.IGNORECASE), "Router OS"),
    (re.compile(r"\bmikrotik\b", re.IGNORECASE), "RouterOS (MikroTik)"),
    (re.compile(r"\bopenwrt\b", re.IGNORECASE), "OpenWrt"),
    (re.compile(r"\bdd-wrt\b", re.IGNORECASE), "DD-WRT"),
    (re.compile(r"\bcisco\b", re.IGNORECASE), "Cisco IOS"),
    (re.compile(r"\bfortinet\b", re.IGNORECASE), "FortiOS"),
    (re.compile(r"\bubiquiti\b", re.IGNORECASE), "Ubiquiti"),
    (re.compile(r"\bunifi\b", re.IGNORECASE), "Ubiquiti UniFi"),
    (re.compile(r"\bsynology\b", re.IGNORECASE), "Synology DSM"),
    (re.compile(r"\bqnap\b", re.IGNORECASE), "QNAP QTS"),
    (re.compile(r"\bfreenas\b", re.IGNORECASE), "FreeNAS / TrueNAS"),
    (re.compile(r"\btruenas\b", re.IGNORECASE), "TrueNAS"),
    (re.compile(r"\bproxmox\b", re.IGNORECASE), "Proxmox VE"),
    (re.compile(r"\bvmware\b", re.IGNORECASE), "VMware ESXi"),
    (re.compile(r"\besxi\b", re.IGNORECASE), "VMware ESXi"),
    (re.compile(r"\bhyper-v\b", re.IGNORECASE), "Hyper-V"),
    (re.compile(r"\bunraid\b", re.IGNORECASE), "Unraid"),
    (re.compile(r"\bplex\b", re.IGNORECASE), "Linux/Unix"),
    (re.compile(r"\bprinter\b", re.IGNORECASE), "Printer Firmware"),
    (re.compile(r"\bcanon\b", re.IGNORECASE), "Canon Firmware"),
    (re.compile(r"\bhp\b", re.IGNORECASE), "HP Firmware"),
    (re.compile(r"\bepson\b", re.IGNORECASE), "Epson Firmware"),
    (re.compile(r"\bbrother\b", re.IGNORECASE), "Brother Firmware"),
    (re.compile(r"\bcamera\b", re.IGNORECASE), "Camera Firmware"),
    (re.compile(r"\bip cam\b", re.IGNORECASE), "Camera Firmware"),
    (re.compile(r"\bhikvision\b", re.IGNORECASE), "Hikvision Firmware"),
    (re.compile(r"\bdahua\b", re.IGNORECASE), "Dahua Firmware"),
    (re.compile(r"\biot\b", re.IGNORECASE), "IoT Firmware"),
    (re.compile(r"\besp\b", re.IGNORECASE), "ESP32/8266"),
    (re.compile(r"\bsonoff\b", re.IGNORECASE), "Tasmota / ESP"),
    (re.compile(r"\btuya\b", re.IGNORECASE), "Tuya IoT"),
    (re.compile(r"\bshelly\b", re.IGNORECASE), "Shelly Firmware"),
    (re.compile(r"\bnas\b", re.IGNORECASE), "NAS OS"),
]


def _text_haystack(device: DeviceRecord) -> str:
    return " ".join(
        v.lower() for v in [device.hostname, device.vendor, *device.notes] if v
    )


def _infer_os_from_text(device: DeviceRecord) -> str | None:
    """Match OS family from hostname, vendor, and notes."""
    haystack = _text_haystack(device)
    for pattern, label in _TEXT_OS_PATTERNS:
        if pattern.search(haystack):
            return label
    return None


def _infer_os_from_banners(ports: list[PortInfo]) -> str | None:
    """Match OS from service banners (SSH, HTTP, FTP, etc.)."""
    for port in ports:
        if not port.banner:
            continue
        for pattern, label in _BANNER_PATTERNS:
            if pattern.search(port.banner):
                return label
    return None


def infer_os_family(device: DeviceRecord) -> str | None:
    """Infer OS family from multiple signal sources.

    Priority order:
      1. Banner grabbing (most specific)
      2. TTL value (from ICMP probe)
      3. Text/hostname/vendor keywords (fallback)
    """
    # 1. Banner-based (highest priority)
    result = _infer_os_from_banners(device.open_ports)
    if result:
        return result

    # 2. TTL-based
    if device.ttl is not None:
        result = _ttl_to_os(device.ttl)
        if result:
            return result[1]

    # 3. Text-based fallback
    return _infer_os_from_text(device)


# ── TTL probe via ICMP ────────────────────────────────────────────────────────


async def probe_ttl(ip_address: str, logger: logging.Logger) -> int | None:
    """Send ICMP echo request and extract TTL from the reply."""
    try:
        from scapy.all import ICMP, IP, sr1  # type: ignore[import]
    except ImportError:
        logger.debug("scapy not available; skipping TTL probe for %s", ip_address)
        return None

    def _probe() -> int | None:
        reply = sr1(IP(dst=ip_address) / ICMP(), timeout=2, verbose=False)
        if reply is None:
            return None
        ttl = reply.ttl  # type: ignore[union-attr]
        return ttl

    try:
        return await asyncio.to_thread(_probe)
    except PermissionError:
        logger.debug("TTL probe needs elevated privileges for %s", ip_address)
    except Exception as exc:
        logger.debug("TTL probe failed for %s: %s", ip_address, exc)
    return None
