from __future__ import annotations

import asyncio
import socket
import ssl
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime

from network_inventory.models import TLSCertificateInfo


def _extract_common_name(
    subject: tuple[tuple[tuple[str, str], ...], ...],
) -> str | None:
    for relative_distinguished_name in subject:
        for key, value in relative_distinguished_name:
            if key == "commonName":
                return value
    return None


def _issuer_to_text(issuer: tuple[tuple[tuple[str, str], ...], ...]) -> str | None:
    parts: list[str] = []
    for relative_distinguished_name in issuer:
        for key, value in relative_distinguished_name:
            if key in {"commonName", "organizationName"}:
                parts.append(value)
    return ", ".join(parts) if parts else None


def _fetch_tls_certificate(
    host: str, port: int, timeout: float
) -> TLSCertificateInfo | None:
    context = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=timeout) as raw_socket:
        with context.wrap_socket(raw_socket, server_hostname=host) as tls_socket:
            cert = tls_socket.getpeercert() or {}

    expires_raw = cert.get("notAfter")
    expires_at: str | None = None
    expired: bool | None = None
    if isinstance(expires_raw, str):
        expires_dt = parsedate_to_datetime(expires_raw)
        if expires_dt.tzinfo is None:
            expires_dt = expires_dt.replace(tzinfo=timezone.utc)
        expires_at = expires_dt.isoformat()
        expired = expires_dt < datetime.now(timezone.utc)

    return TLSCertificateInfo(
        common_name=_extract_common_name(cert.get("subject", ())),  # type: ignore[arg-type]
        issuer=_issuer_to_text(cert.get("issuer", ())),  # type: ignore[arg-type]
        expires_at=expires_at,
        expired=expired,
    )


async def fetch_tls_certificate(
    host: str, port: int = 443, timeout: float = 3.0
) -> TLSCertificateInfo | None:
    try:
        return await asyncio.to_thread(_fetch_tls_certificate, host, port, timeout)
    except (OSError, ssl.SSLError, TimeoutError):
        return None
