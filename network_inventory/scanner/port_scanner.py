from __future__ import annotations

import asyncio
import logging
import shutil

from network_inventory.models import PortInfo


COMMON_PORTS: dict[int, str] = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    53: "DNS",
    80: "HTTP",
    81: "HTTP-ALT",
    88: "Kerberos",
    110: "POP3",
    123: "NTP",
    135: "RPC",
    139: "NetBIOS",
    143: "IMAP",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    548: "AFP",  # Apple Filing Protocol → Mac/NAS
    554: "RTSP",  # CCTV / IP Camera
    631: "IPP",  # Printer
    1883: "MQTT",  # IoT broker
    1900: "SSDP",
    3389: "RDP",
    3000: "HTTP-DEV",
    3306: "MySQL",
    4040: "HTTP-ALT",
    5000: "HTTP-ALT",
    5353: "mDNS",
    5555: "ADB",  # Android Debug Bridge → Android phone
    5900: "VNC",
    5985: "WinRM",
    6881: "BitTorrent",
    7000: "HTTP-ALT",
    8080: "HTTP-ALT",
    8081: "HTTP-ALT",
    8443: "HTTPS-ALT",
    8888: "HTTP-ALT",
    9100: "RAW-PRINT",  # Printer (JetDirect)
    9200: "Elasticsearch",
    32400: "Plex",  # Plex Media Server
    49152: "UPnP",
    62078: "iPhone-Sync",  # Apple iTunes sync → iPhone
}


def _nmap_binary_available() -> bool:
    return shutil.which("nmap") is not None


async def scan_common_ports_nmap(
    ip_address: str,
    logger: logging.Logger,
    timeout: float = 1.5,
) -> list[PortInfo]:
    try:
        import nmap
    except ImportError:
        return []
    if not _nmap_binary_available():
        logger.debug(
            "nmap binary not found in PATH; skipping nmap scan for %s", ip_address
        )
        return []

    def _scan() -> list[PortInfo]:
        scanner = nmap.PortScanner()
        port_list = ",".join(str(p) for p in COMMON_PORTS.keys())
        scanner.scan(
            hosts=ip_address,
            arguments=f"-Pn -sT -sV --host-timeout {int(timeout * 1000)}ms -p {port_list}",
        )
        if ip_address not in scanner.all_hosts():
            return []
        ports: list[PortInfo] = []
        host_data = scanner[ip_address]
        for port, meta in host_data.get("tcp", {}).items():
            if int(port) not in COMMON_PORTS:
                continue
            ports.append(
                PortInfo(
                    port=int(port),
                    service=meta.get("name") or COMMON_PORTS[int(port)],
                    open=meta.get("state") == "open",
                    banner=meta.get("product") or meta.get("extrainfo") or None,
                    version=meta.get("version") or None,
                )
            )
        return ports

    try:
        return await asyncio.to_thread(_scan)
    except Exception as exc:
        logger.debug("nmap scan failed for %s: %s", ip_address, exc)
        return []


async def scan_port(
    ip_address: str, port: int, service: str, timeout: float, logger: logging.Logger
) -> PortInfo:
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip_address, port), timeout=timeout
        )
        banner: str | None = None
        try:
            raw_banner = await asyncio.wait_for(reader.read(128), timeout=0.8)
            if raw_banner:
                banner = raw_banner.decode("utf-8", errors="replace").strip()
        except (asyncio.TimeoutError, ConnectionError):
            pass
        writer.close()
        await writer.wait_closed()
        return PortInfo(port=port, service=service, open=True, banner=banner)
    except (asyncio.TimeoutError, OSError, ConnectionError) as exc:
        logger.debug("Port %s/%s closed or filtered: %s", ip_address, port, exc)
        return PortInfo(port=port, service=service, open=False)


async def scan_common_ports(
    ip_address: str,
    logger: logging.Logger,
    timeout: float = 1.5,
    concurrency: int = 32,
) -> list[PortInfo]:
    nmap_results = await scan_common_ports_nmap(ip_address, logger, timeout=timeout)
    if nmap_results:
        return nmap_results

    semaphore = asyncio.Semaphore(concurrency)

    async def _limited_scan(port: int, service: str) -> PortInfo:
        async with semaphore:
            return await scan_port(ip_address, port, service, timeout, logger)

    results = await asyncio.gather(
        *(_limited_scan(port, service) for port, service in COMMON_PORTS.items())
    )
    return [result for result in results if result.open]
