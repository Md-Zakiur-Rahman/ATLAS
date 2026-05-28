"""
ATLAS USB Monitor

Detects newly connected removable drives
and publishes USB device events.
"""

import logging
import threading
import time
from typing import Set

import psutil

from core.runtime_state import runtime_state
from config.logging_config import get_logger
from monitor import rules
from monitor.event_bus import event_bus

logger = get_logger("usb_monitor")


class USBMonitor:

    def __init__(self):

        self._stop_event = threading.Event()

        self._thread = None

        self.known_devices: Set[str] = set()

    def start(self):

        if self._thread and self._thread.is_alive():
            return

        self._stop_event.clear()

        self._thread = threading.Thread(
            target=self._monitor_loop,
            daemon=True
        )

        self._thread.start()

        logger.info("USB Monitor Started")
        runtime_state.set_nested("monitor_states", {"usb_monitor": True})

    def stop(self):

        self._stop_event.set()

        if self._thread:
            self._thread.join(timeout=2)

        logger.info("USB Monitor Stopped")
        runtime_state.set_nested("monitor_states", {"usb_monitor": False})

    def _monitor_loop(self):

        while not self._stop_event.is_set():

            self._scan_devices()

            self._stop_event.wait(
                rules.USB_SCAN_INTERVAL_SECONDS
            )

    def _scan_devices(self):

        current_devices = set()

        for partition in psutil.disk_partitions(all=False):
            logger.info(
                "Detected Partition: %s",
                partition.device
                )

            try:

                options = partition.opts.lower() if partition.opts else ""
                if "removable" not in options:
                    continue

                device = partition.device

                current_devices.add(device)

                if device not in self.known_devices:

                    self.known_devices.add(device)

                    logger.warning(
                        "USB/External Device Connected: %s",
                        device
                    )

                    event_bus.publish(
                        {
                            "event_type": "USB_DEVICE_CONNECTED",
                            "device": device,
                            "timestamp": time.time()
                        }
                    )

            except Exception as error:

                logger.debug(
                    "USB Scan Error: %s",
                    error
                )

        self.known_devices = current_devices
        runtime_state.set_devices(sorted(current_devices))


usb_monitor = USBMonitor()


def start_usb_monitor():

    usb_monitor.start()


def stop_usb_monitor():

    usb_monitor.stop()
