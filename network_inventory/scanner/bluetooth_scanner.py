from __future__ import annotations

import asyncio
import logging
import threading

from network_inventory.models import BluetoothDevice


async def discover_bluetooth(
    logger: logging.Logger, timeout: float = 8.0
) -> list[BluetoothDevice]:
    try:
        from bleak import BleakScanner  # type: ignore[import]
    except ImportError:
        logger.warning("bleak is not installed; skipping Bluetooth discovery")
        return []

    result_holder: list[BluetoothDevice] = []
    error_holder: list[Exception] = []

    def _run_in_thread() -> None:
        """Run BLE scan in a fresh thread with its own asyncio event loop.

        This avoids the Windows GUI-thread / asyncio conflict that causes
        'Thread is configured for Windows GUI but callbacks are not working'.
        """
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            devices = loop.run_until_complete(BleakScanner.discover(timeout=timeout))
            for device in devices:
                result_holder.append(
                    BluetoothDevice(
                        name=device.name,
                        address=device.address,
                        rssi=getattr(device, "rssi", None),
                    )
                )
        except Exception as exc:  # noqa: BLE001
            error_holder.append(exc)
        finally:
            loop.close()

    thread = threading.Thread(target=_run_in_thread, daemon=True)
    thread.start()
    # Yield to event loop while waiting — don't block the entire scan
    await asyncio.to_thread(thread.join, timeout + 2)

    if error_holder:
        logger.warning("Bluetooth discovery failed: %s", error_holder[0])
        return []

    return result_holder
