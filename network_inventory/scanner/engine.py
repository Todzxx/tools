from __future__ import annotations

import asyncio
import ipaddress
import logging
import subprocess
import platform
from typing import Any, Protocol
from urllib.parse import urlparse

from network_inventory.detectors.device_classifier import classify_device
from network_inventory.detectors.os_detector import infer_os_family, probe_ttl
from network_inventory.detectors.vendor_detector import VendorDetector
from network_inventory.models import (
    DeviceRecord,
    MdnsService,
    OnvifDevice,
    ScanResult,
    SsdpDevice,
)
from network_inventory.scanner.arp_scanner import arp_scan, tcp_sweep, icmp_ping
from network_inventory.scanner.ipv6_scanner import discover_ipv6_neighbors
from network_inventory.scanner.nmap_scanner import discover_hosts as nmap_discover
from network_inventory.scanner.router_scanner import scrape_dhcp_leases
from network_inventory.scanner.bluetooth_scanner import discover_bluetooth
from network_inventory.scanner.mdns_scanner import discover_mdns
from network_inventory.scanner.onvif_scanner import discover_onvif
from network_inventory.scanner.snmp_scanner import batch_snmp_scan
from network_inventory.scanner.netbios_scanner import batch_netbios_scan
from network_inventory.scanner.port_scanner import scan_common_ports
from network_inventory.scanner.service_detector import enrich_service
from network_inventory.scanner.ssdp_scanner import discover_ssdp
from network_inventory.scanner.wifi_scanner import scan_wifi
from network_inventory.utils.dns_utils import reverse_dns_lookup
from network_inventory.utils.tls_utils import fetch_tls_certificate


class ProgressReporter(Protocol):
    def set_info(self, stage: str, info: str) -> None: ...
    def set_detail(self, stage: str, detail: str) -> None: ...
    def finish_stage(self, stage: str) -> None: ...
    def set_device_count(self, count: int) -> None: ...
    def add_stage(self, key: str, label: str, total: int = 0) -> None: ...
    def update_progress(self, key: str, advance: int = 1) -> None: ...


class ScannerEngine:
    """Professional scanning engine that orchestrates multiple discovery methods."""

    def __init__(
        self, logger: logging.Logger, progress: ProgressReporter | None = None
    ):
        self.logger = logger
        self.progress = progress
        self.vendor_detector = VendorDetector(logger)

    def validate_target(
        self, raw_target: str, allow_public: bool, max_hosts: int
    ) -> ipaddress.IPv4Network:
        try:
            network = ipaddress.ip_network(raw_target, strict=False)
        except ValueError as exc:
            raise ValueError(f"Invalid target: {exc}")

        if not isinstance(network, ipaddress.IPv4Network):
            raise ValueError("Only IPv4 CIDR is supported currently.")

        if not allow_public and not (
            network.is_private or network.is_link_local or network.is_loopback
        ):
            raise ValueError(
                "Target must be a private/local network. Use --allow-public if authorized."
            )

        if network.num_addresses > max_hosts + 2:
            raise ValueError(
                f"Target size ({network.num_addresses}) exceeds safety limit ({max_hosts})."
            )

        return network

    async def run(self, target: str, options: dict[str, Any]) -> ScanResult:
        """Main execution flow for a complete network scan."""
        allow_public = options.get("allow_public", False)
        max_hosts = options.get("max_hosts", 1024)

        if self.progress:
            self.progress.add_stage("arp", "ARP Discovery")
            if options.get("use_nmap"):
                self.progress.add_stage("nmap", "Nmap Discovery")
            if options.get("use_dhcp"):
                self.progress.add_stage("dhcp", "DHCP Scraping")
            self.progress.add_stage("icmp", "ICMP Sweep")
            self.progress.add_stage("tcp", "TCP Sweep")
            if options.get("use_ipv6"):
                self.progress.add_stage("ipv6", "IPv6 Discovery")
            if options.get("use_snmp"):
                self.progress.add_stage("snmp", "SNMP Discovery")
            self.progress.add_stage("netbios", "NetBIOS Discovery")
            self.progress.add_stage("passive", "Passive Discovery")

        network = self.validate_target(target, allow_public, max_hosts)
        result = ScanResult.start(str(network))
        devices: dict[str, DeviceRecord] = {}

        self.logger.info("Starting professional scan for %s", network)

        # 0. Warm-up Phase (Trigger traffic to wake up silent devices)
        if self.progress:
            self.progress.set_info("arp", "warming up network...")
        await self._warm_up(network)

        # 1. Layer 2 Discovery (ARP)
        await self._step_arp(network, devices)

        # 2. Nmap Discovery
        if options.get("use_nmap"):
            await self._step_nmap(network, devices)

        # 3. DHCP Scraping
        if options.get("use_dhcp"):
            router_ip = options.get("router_ip")
            if not router_ip:
                try:
                    router_ip = str(next(network.hosts()))
                except StopIteration:
                    router_ip = str(network.network_address)
            await self._step_dhcp(router_ip, network, devices, options)

        # 4. ICMP Sweep
        await self._step_icmp(network, devices)

        # 5. TCP Sweep
        await self._step_tcp(network, devices)

        # 6. IPv6 Discovery
        if options.get("use_ipv6"):
            await self._step_ipv6(network, devices)

        # 7. SNMP Discovery
        if options.get("use_snmp"):
            try:
                await self._step_snmp(
                    devices, options.get("snmp_communities", ["public"])
                )
            except Exception as e:
                self.logger.error("SNMP step failed: %s", e)
                if self.progress:
                    self.progress.set_info("snmp", "failed")

        # 8. NetBIOS Discovery
        await self._step_netbios(devices)

        # 9. Passive Discovery (mDNS, SSDP, etc.)
        try:
            await self._step_passive(result, devices)
        except Exception as e:
            self.logger.error("Passive discovery failed: %s", e)
            if self.progress:
                self.progress.set_info("passive", "failed")

        # 10. Final Cleanup: Filter out broadcast/network addresses
        network_addr_str = str(network.network_address)
        broadcast_addr_str = str(network.broadcast_address)
        for ip in list(devices.keys()):
            if ip == network_addr_str or ip == broadcast_addr_str:
                del devices[ip]

        # 11. Device Enrichment (Port scans, DNS, TLS)
        await self._step_enrich(devices, options.get("timeout", 2.0))

        result.devices = list(devices.values())
        result.finish()
        return result

    async def _step_snmp(
        self, devices: dict[str, DeviceRecord], communities: list[str]
    ):
        if not devices:
            return
        if self.progress:
            self.progress.set_info("snmp", "probing SNMP...")

        found = await batch_snmp_scan(list(devices.keys()), communities, self.logger)
        for ip, info in found.items():
            dev = devices[ip]
            if info.sys_name:
                dev.hostname = dev.hostname or info.sys_name

            note = (
                f"SNMP: {info.sys_descr[:50]}..." if info.sys_descr else "SNMP: active"
            )
            if note not in dev.notes:
                dev.notes.append(note)

            if info.sys_location:
                dev.notes.append(f"Location: {info.sys_location}")

        if self.progress:
            self.progress.set_info("snmp", f"{len(found)} active")
            self.progress.finish_stage("snmp")

    async def _step_netbios(self, devices: dict[str, DeviceRecord]):
        if not devices:
            return
        if self.progress:
            self.progress.set_info("netbios", "querying names...")

        found = await batch_netbios_scan(list(devices.keys()), self.logger)
        for ip, name in found.items():
            dev = devices[ip]
            dev.hostname = dev.hostname or name
            note = f"NetBIOS: {name}"
            if note not in dev.notes:
                dev.notes.append(note)

        if self.progress:
            self.progress.set_info("netbios", f"{len(found)} named")
            self.progress.finish_stage("netbios")

    async def _step_arp(
        self, network: ipaddress.IPv4Network, devices: dict[str, DeviceRecord]
    ):
        if self.progress:
            self.progress.set_info("arp", "scanning...")

        found = await arp_scan(network, self.vendor_detector, self.logger)
        for dev in found:
            self._merge_device(devices, dev)

        if self.progress:
            self.progress.set_info("arp", f"{len(found)} found")
            self.progress.finish_stage("arp")
            self.progress.set_device_count(len(devices))

    async def _step_nmap(
        self, network: ipaddress.IPv4Network, devices: dict[str, DeviceRecord]
    ):
        if self.progress:
            self.progress.set_info("nmap", "fingerprinting...")

        found = await nmap_discover(network, self.logger)
        for dev in found:
            self._merge_device(devices, dev)

        if self.progress:
            self.progress.set_info("nmap", f"{len(found)} found")
            self.progress.finish_stage("nmap")

    async def _step_dhcp(
        self,
        router_ip: str,
        network: ipaddress.IPv4Network,
        devices: dict[str, DeviceRecord],
        options: dict[str, Any] | None = None,
    ):
        if self.progress:
            self.progress.set_info("dhcp", f"scraping {router_ip}...")

        username = options.get("router_username", "admin") if options else "admin"
        password = options.get("router_password", "admin") if options else "admin"
        found = await scrape_dhcp_leases(
            router_ip, self.logger, username=username, password=password
        )
        for dev in found:
            if ipaddress.ip_address(dev.ip_address) in network:
                self._merge_device(devices, dev)
                # Resolve vendor if missing
                if dev.mac_address and not devices[dev.ip_address].vendor:
                    devices[dev.ip_address].vendor = await self.vendor_detector.detect(
                        dev.mac_address
                    )

        if self.progress:
            self.progress.set_info("dhcp", f"{len(found)} found")
            self.progress.finish_stage("dhcp")

    async def _step_icmp(
        self, network: ipaddress.IPv4Network, devices: dict[str, DeviceRecord]
    ):
        if self.progress:
            self.progress.set_info("icmp", "pinging...")

        before = len(devices)
        semaphore = asyncio.Semaphore(128)

        async def probe(ip: str):
            async with semaphore:
                if ip in devices:
                    return
                if await icmp_ping(ip, self.logger):
                    devices[ip] = DeviceRecord(ip_address=ip)

        await asyncio.gather(*(probe(str(h)) for h in network.hosts()))

        if self.progress:
            self.progress.set_info("icmp", f"{len(devices) - before} new")
            self.progress.finish_stage("icmp")

    async def _step_tcp(
        self, network: ipaddress.IPv4Network, devices: dict[str, DeviceRecord]
    ):
        if self.progress:
            self.progress.set_info("tcp", "probing ports...")

        known_ips = set(devices.keys())
        found_ips = await tcp_sweep(network, known_ips, self.logger)

        new_count = 0
        for ip in found_ips:
            if ip not in devices:
                devices[ip] = DeviceRecord(ip_address=ip)
                new_count += 1

        if self.progress:
            self.progress.set_info("tcp", f"{new_count} new")
            self.progress.finish_stage("tcp")

    async def _step_ipv6(
        self, network: ipaddress.IPv4Network, devices: dict[str, DeviceRecord]
    ):
        if self.progress:
            self.progress.set_info("ipv6", "reading ND cache...")

        found = await discover_ipv6_neighbors(self.logger, str(network))
        new_count = 0
        for nd in found:
            # Merge by MAC if possible
            existing = None
            if nd.mac_address:
                existing = next(
                    (d for d in devices.values() if d.mac_address == nd.mac_address),
                    None,
                )

            if existing:
                existing.ipv6_address = existing.ipv6_address or nd.ipv6_address
            elif nd.ip_address not in devices:
                devices[nd.ip_address] = nd
                new_count += 1

        if self.progress:
            self.progress.set_info("ipv6", f"{new_count} new")
            self.progress.finish_stage("ipv6")

    async def _step_passive(self, result: ScanResult, devices: dict[str, DeviceRecord]):
        if self.progress:
            self.progress.set_info("passive", "listening...")

        tasks = {
            "ssdp": asyncio.create_task(discover_ssdp(self.logger)),
            "mdns": asyncio.create_task(discover_mdns(self.logger)),
            "onvif": asyncio.create_task(discover_onvif(self.logger)),
            "wifi": asyncio.create_task(scan_wifi(self.logger)),
            "bluetooth": asyncio.create_task(discover_bluetooth(self.logger)),
        }

        result.ssdp_devices = await tasks["ssdp"]  # type: ignore[assignment]
        result.mdns_services = await tasks["mdns"]  # type: ignore[assignment]
        result.onvif_devices = await tasks["onvif"]  # type: ignore[assignment]
        result.wifi_networks = await tasks["wifi"]  # type: ignore[assignment]
        result.bluetooth_devices = await tasks["bluetooth"]  # type: ignore[assignment]

        self._attach_discovery_notes(
            devices, result.ssdp_devices, result.mdns_services, result.onvif_devices
        )

        if self.progress:
            self.progress.set_info("passive", f"{len(devices)} total")
            self.progress.finish_stage("passive")

    async def _step_enrich(self, devices: dict[str, DeviceRecord], timeout: float):
        if not devices:
            return

        if self.progress:
            self.progress.add_stage("enrich", "Enrichment", total=len(devices))

        semaphore = asyncio.Semaphore(64)

        async def enrich_one(device: DeviceRecord):
            async with semaphore:
                # DNS, Ports, TTL, OS, TLS
                hostname_task = asyncio.create_task(
                    reverse_dns_lookup(device.ip_address)
                )
                ports_task = asyncio.create_task(
                    scan_common_ports(device.ip_address, self.logger, timeout=timeout)
                )
                ttl_task = asyncio.create_task(
                    probe_ttl(device.ip_address, self.logger)
                )

                device.hostname = await hostname_task
                ports = await ports_task
                device.ttl = await ttl_task
                device.open_ports = [enrich_service(p) for p in ports]

                if any(p.port == 443 for p in device.open_ports):
                    device.tls = await fetch_tls_certificate(
                        device.ip_address, 443, timeout=timeout + 1.0
                    )

                device.device_type = classify_device(device)
                device.os_family = infer_os_family(device)

                if self.progress:
                    self.progress.update_progress("enrich")

        await asyncio.gather(*(enrich_one(d) for d in devices.values()))

    def _merge_device(self, devices: dict[str, DeviceRecord], new_dev: DeviceRecord):
        current = devices.get(new_dev.ip_address)
        if current:
            current.mac_address = current.mac_address or new_dev.mac_address
            current.vendor = current.vendor or new_dev.vendor
            current.hostname = current.hostname or new_dev.hostname
            current.os_family = current.os_family or new_dev.os_family
        else:
            devices[new_dev.ip_address] = new_dev

    def _attach_discovery_notes(
        self,
        devices: dict[str, DeviceRecord],
        ssdp: list[SsdpDevice],
        mdns: list[MdnsService],
        onvif: list[OnvifDevice],
    ):
        # mDNS - HP dan IoT biasanya muncul di sini
        for srv in mdns:
            for addr in srv.addresses:
                # Jika perangkat belum ada di list utama, masukkan!
                if addr not in devices:
                    devices[addr] = DeviceRecord(
                        ip_address=addr, hostname=srv.server or srv.name
                    )

                dev = devices[addr]
                note = f"mDNS: {srv.name} ({srv.service_type})"
                if note not in dev.notes:
                    dev.notes.append(note)
                if not dev.hostname or dev.hostname == "-":
                    dev.hostname = srv.server or srv.name

        # SSDP - Smart TV dan Router biasanya muncul di sini
        for sd in ssdp:
            if not sd.location:
                continue
            host = urlparse(sd.location).hostname
            if host and self._is_ip(host):
                if host not in devices:
                    devices[host] = DeviceRecord(ip_address=host)
                dev = devices[host]
                note = f"SSDP: {' / '.join(filter(None, [sd.manufacturer, sd.model, sd.server]))}"
                if note not in dev.notes:
                    dev.notes.append(note)
                if not dev.vendor and sd.manufacturer:
                    dev.vendor = sd.manufacturer

        # ONVIF
        for od in onvif:
            host = urlparse(od.endpoint).hostname
            if host and self._is_ip(host):
                if host not in devices:
                    devices[host] = DeviceRecord(ip_address=host)
                dev = devices[host]
                note = f"ONVIF: {' / '.join(filter(None, [od.manufacturer, od.model]))}"
                if note not in dev.notes:
                    dev.notes.append(note)
                if not dev.vendor and od.manufacturer:
                    dev.vendor = od.manufacturer

    def _is_ip(self, val: str) -> bool:
        try:
            ipaddress.ip_address(val)
            return True
        except ValueError:
            return False

    async def _warm_up(self, network: ipaddress.IPv4Network):
        """Sends broadcast ICMP to wake up devices and populate ARP tables."""
        broadcast = str(network.broadcast_address)
        try:
            if platform.system() == "Windows":
                # Windows ping doesn't support broadcast well, so we ping a few likely IPs
                ips_to_poke = [
                    str(network.network_address + i) for i in [1, 2, 5, 10, 254]
                ]
                tasks = [
                    asyncio.to_thread(
                        subprocess.run,
                        ["ping", "-n", "1", "-w", "200", ip],
                        capture_output=True,
                    )
                    for ip in ips_to_poke
                ]
                await asyncio.gather(*tasks)
            else:
                subprocess.run(
                    ["ping", "-b", "-c", "1", "-W", "1", broadcast], capture_output=True
                )
        except Exception as exc:
            self.logger.debug("Warm-up ping failed: %s", exc)
