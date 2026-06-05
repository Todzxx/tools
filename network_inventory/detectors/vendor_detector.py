from __future__ import annotations

import asyncio
import logging


class VendorDetector:
    def __init__(self, logger: logging.Logger) -> None:
        self._logger = logger
        self._lookup = None
        self._loaded = False
        try:
            from mac_vendor_lookup import MacLookup
            self._lookup = MacLookup()
        except ImportError:
            self._logger.warning("mac-vendor-lookup is not installed")

    async def _ensure_loaded(self) -> None:
        if self._lookup and not self._loaded:
            try:
                await asyncio.to_thread(self._lookup.load_vendors)
                self._loaded = True
            except Exception as exc:
                self._logger.warning("MAC vendor database could not be loaded: %s", exc)

    async def detect(self, mac_address: str | None) -> str | None:
        if not mac_address or self._lookup is None:
            return None

        normalized_mac = mac_address.replace("-", ":").upper()

        await self._ensure_loaded()
        try:
            return await asyncio.to_thread(self._lookup.lookup, normalized_mac)
        except Exception as exc:
            self._logger.debug("Vendor lookup failed for %s: %s", normalized_mac, exc)
            return None
