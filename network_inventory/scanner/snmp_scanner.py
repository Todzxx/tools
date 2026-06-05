from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass

from pysnmp.hlapi.asyncio import (
    ContextData,
    CommunityData,
    ObjectIdentity,
    ObjectType,
    SnmpEngine,
    UdpTransportTarget,
    get_cmd,
)


@dataclass
class SnmpInfo:
    sys_name: str | None = None
    sys_descr: str | None = None
    sys_location: str | None = None


# Standard MIB-2 OIDs for system information
OIDS = {
    "sysDescr": "1.3.6.1.2.1.1.1.0",
    "sysName": "1.3.6.1.2.1.1.5.0",
    "sysLocation": "1.3.6.1.2.1.1.6.0",
}


async def probe_snmp(
    ip_address: str,
    community: str = "public",
    timeout: float = 1.0,
    port: int = 161,
) -> SnmpInfo | None:
    """Probes a device for basic system information using SNMP v2c."""

    snmp_engine = SnmpEngine()
    community_data = CommunityData(community, mpModel=1)  # v2c
    transport_target = await UdpTransportTarget.create(
        (ip_address, port), timeout=timeout, retryCount=0
    )
    context_data = ContextData()

    object_types = [ObjectType(ObjectIdentity(oid)) for oid in OIDS.values()]

    try:
        # Run the GET command
        error_indication, error_status, error_index, var_binds = await get_cmd(
            snmp_engine,
            community_data,
            transport_target,
            context_data,
            *object_types,
        )

        if error_indication:
            return None
        elif error_status:
            return None
        else:
            info = SnmpInfo()
            # Map results back to info object
            results = {str(vb[0]): str(vb[1]) for vb in var_binds}

            info.sys_descr = results.get(OIDS["sysDescr"])
            info.sys_name = results.get(OIDS["sysName"])
            info.sys_location = results.get(OIDS["sysLocation"])

            return info

    except Exception as exc:
        logging.getLogger(__name__).debug("SNMP probe %s failed: %s", ip_address, exc)
        return None
    finally:
        snmp_engine.close_dispatcher()


async def batch_snmp_scan(
    ip_addresses: list[str],
    communities: list[str],
    logger: logging.Logger,
    timeout: float = 1.0,
) -> dict[str, SnmpInfo]:
    """Scans multiple IPs for SNMP in parallel."""
    results: dict[str, SnmpInfo] = {}
    semaphore = asyncio.Semaphore(100)

    async def _probe(ip: str):
        async with semaphore:
            for comm in communities:
                info = await probe_snmp(ip, comm, timeout)
                if info and (info.sys_name or info.sys_descr):
                    results[ip] = info
                    break

    await asyncio.gather(*(_probe(ip) for ip in ip_addresses))
    return results
