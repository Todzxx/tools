from __future__ import annotations

import re

from network_inventory.models import DeviceRecord


# ── Vendor-based type map ─────────────────────────────────────────────────────
# If port/text classification can't determine the type, fall back to vendor.
VENDOR_TYPE_MAP: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"(?i)\bsamsung\b.*(?:electron|mobile|comm)"), "Smartphone"),
    (re.compile(r"(?i)\bapple\b"),                              "iPhone"),
    (re.compile(r"(?i)\bxiaomi\b"),                              "Smartphone"),
    (re.compile(r"(?i)\bhuawei\b"),                              "Smartphone"),
    (re.compile(r"(?i)\bopp\b"),                                "Smartphone"),
    (re.compile(r"(?i)\bvivo\b"),                               "Smartphone"),
    (re.compile(r"(?i)\boneplus\b"),                            "Smartphone"),
    (re.compile(r"(?i)\bgoogle\b"),                              "Smartphone"),
    (re.compile(r"(?i)\blg\s*electron\b"),                       "Smartphone"),
    (re.compile(r"(?i)\bmotorola\b"),                            "Smartphone"),
    (re.compile(r"(?i)\bnokia\b"),                               "Smartphone"),
    (re.compile(r"(?i)\brealme\b"),                              "Smartphone"),
    (re.compile(r"(?i)\b(tp-?link|tplink)\b"),                  "Router"),
    (re.compile(r"(?i)\basustek\b"),                             "Router"),
    (re.compile(r"(?i)\bnetgear\b"),                             "Router"),
    (re.compile(r"(?i)\bcisco\b"),                               "Router"),
    (re.compile(r"(?i)\bmikrotik\b"),                            "Router"),
    (re.compile(r"(?i)\bubiquiti\b"),                            "Router"),
    (re.compile(r"(?i)\bd-?link\b"),                             "Router"),
    (re.compile(r"(?i)\blinksys\b"),                             "Router"),
    (re.compile(r"(?i)\btenda\b"),                               "Router"),
    (re.compile(r"(?i)\bzte\b"),                                 "Router"),
    (re.compile(r"(?i)\bcanon\b"),                               "Printer"),
    (re.compile(r"(?i)\bepson\b"),                               "Printer"),
    (re.compile(r"(?i)\bbrother\b"),                             "Printer"),
    (re.compile(r"(?i)\b(hewlett-?packard|hp)\b"),              "Printer"),
    (re.compile(r"(?i)\bkyocera\b"),                             "Printer"),
    (re.compile(r"(?i)\bricoh\b"),                               "Printer"),
    (re.compile(r"(?i)\bhikvision\b"),                           "CCTV"),
    (re.compile(r"(?i)\bdahua\b"),                               "CCTV"),
    (re.compile(r"(?i)\baxis\s*comm\b"),                         "CCTV"),
    (re.compile(r"(?i)\bdell\b"),                                "Laptop"),
    (re.compile(r"(?i)\blenovo\b"),                              "Laptop"),
    (re.compile(r"(?i)\b(acer|eMachines)\b"),                   "Laptop"),
    (re.compile(r"(?i)\bsynology\b"),                            "NAS"),
    (re.compile(r"(?i)\bqnap\b"),                                "NAS"),
    (re.compile(r"(?i)\b(wester[n]?\s*digital|seagate)\b"),     "NAS"),
    (re.compile(r"(?i)\bsony\b"),                                "Smart TV"),
    (re.compile(r"(?i)\bphilips\b"),                             "Smart TV"),
    (re.compile(r"(?i)\bespressif\b"),                           "IoT"),
    (re.compile(r"(?i)\b(raspberry\s*pi|rpi)\b"),               "IoT"),
    (re.compile(r"(?i)\bintel\b"),                               "Desktop"),
    (re.compile(r"(?i)\bamd\b"),                                 "Desktop"),
]


# ── Port-based fingerprint sets ───────────────────────────────────────────────
PRINTER_PORTS   = {631, 9100}           # IPP, JetDirect
CCTV_PORTS      = {554, 8554}           # RTSP
NAS_PORTS       = {445, 139, 21, 548}   # SMB, NetBIOS, FTP, AFP
ANDROID_PORTS   = {5555}               # ADB
IPHONE_PORTS    = {62078}              # iTunes sync
PLEX_PORTS      = {32400}              # Plex Media Server
SMART_TV_PORTS  = {8008, 8009, 7000}   # Chromecast / TV
WINDOWS_PORTS   = {445, 3389, 135}     # SMB + RDP + RPC
MAC_PORTS       = {548, 5900}          # AFP + VNC
ROUTER_PORTS    = {53, 80, 443}        # DNS + Web UI
IOT_PORTS       = {1883, 8883}         # MQTT


def _ports(device: DeviceRecord) -> set[int]:
    return {p.port for p in device.open_ports if p.open}


def _text(device: DeviceRecord) -> str:
    return " ".join(
        v.lower() for v in [device.hostname, device.vendor, *device.notes] if v
    )


def _classify_by_vendor(device: DeviceRecord) -> str | None:
    if not device.vendor:
        return None
    for pattern, dtype in VENDOR_TYPE_MAP:
        if pattern.search(device.vendor):
            return dtype
    return None


def classify_device(device: DeviceRecord) -> str:  # noqa: PLR0911
    text = _text(device)
    open_ports = _ports(device)

    # ── Printers ──────────────────────────────────────────────────────────────
    if "printer" in text or PRINTER_PORTS & open_ports:
        return "Printer"

    # ── CCTV / IP Camera ──────────────────────────────────────────────────────
    if (
        "camera" in text
        or "onvif" in text
        or "rtsp" in text
        or "hikvision" in text
        or "dahua" in text
        or CCTV_PORTS & open_ports
    ):
        return "CCTV"

    # ── NAS / File Server ─────────────────────────────────────────────────────
    if "nas" in text or "synology" in text or "qnap" in text or "freenas" in text:
        return "NAS"
    if (
        445 in open_ports
        and 139 in open_ports
        and not any(
            kw in text
            for kw in ["desktop", "laptop", "notebook", "macbook", "windows"]
        )
    ):
        return "NAS"

    # ── Smart TV / Media Player ───────────────────────────────────────────────
    if (
        "chromecast" in text
        or "roku" in text
        or "smart-tv" in text
        or "smart tv" in text
        or "bravia" in text
        or "webos" in text
        or SMART_TV_PORTS & open_ports
    ):
        if PLEX_PORTS & open_ports:
            return "Plex Server"
        return "Smart TV"

    # ── Plex Media Server ─────────────────────────────────────────────────────
    if PLEX_PORTS & open_ports or "plex" in text:
        return "Plex Server"

    # ── Android Phone / Device ────────────────────────────────────────────────
    if ANDROID_PORTS & open_ports or "android" in text:
        return "Android"

    # ── iPhone / Apple Device ─────────────────────────────────────────────────
    if IPHONE_PORTS & open_ports or "iphone" in text or "apple" in text:
        return "iPhone"

    # ── Router / Gateway ──────────────────────────────────────────────────────
    if any(
        keyword in text
        for keyword in ["router", "gateway", "mikrotik", "tp-link", "tplink",
                        "asus", "netgear", "ubiquiti", "unifi", "openwrt",
                        "dd-wrt", "fortinet", "cisco"]
    ):
        return "Router"

    # ── Access Point ──────────────────────────────────────────────────────────
    if "access point" in text or "ap-" in text or " ap " in text:
        return "Access Point"

    # ── Windows PC ────────────────────────────────────────────────────────────
    if WINDOWS_PORTS.issubset(open_ports):
        return "Windows PC"
    if 3389 in open_ports and 445 in open_ports:
        return "Windows PC"

    # ── Mac ───────────────────────────────────────────────────────────────────
    if MAC_PORTS & open_ports or "macbook" in text or "mac-" in text:
        return "Mac"

    # ── Smartphone (generic) ──────────────────────────────────────────────────
    if any(
        token in text
        for token in ["samsung", "xiaomi", "oppo", "vivo", "huawei", "realme"]
    ):
        return "Smartphone"

    # ── Laptop ────────────────────────────────────────────────────────────────
    if any(token in text for token in ["laptop", "notebook"]):
        return "Laptop"

    # ── Desktop / PC ──────────────────────────────────────────────────────────
    if any(token in text for token in ["desktop", "pc-", "workstation"]):
        return "Desktop"

    # ── IoT device ────────────────────────────────────────────────────────────
    if (
        "iot" in text
        or "esp" in text
        or "sonoff" in text
        or "tuya" in text
        or "shelly" in text
        or IOT_PORTS & open_ports
    ):
        return "IoT"

    # ── Fallback: router-like (DNS + web UI) ──────────────────────────────────
    if ROUTER_PORTS.issubset(open_ports):
        return "Router"

    # ── Fallback: vendor-based (when ports/hostname give no clue) ────────────
    vendor_type = _classify_by_vendor(device)
    if vendor_type:
        return vendor_type

    return "Unknown"
