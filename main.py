"""
ATLAS Main Launcher

Initializes:
- Threat Engine
- File Monitor
- Process Monitor
- Event Bus Connections
"""

import logging
from time import sleep

from monitor.event_bus import event_bus
from monitor.file_monitor import (
    start_monitor,
    stop_monitor
)
from monitor.process_monitor import (
    start_process_monitor,
    stop_process_monitor
)
from monitor.threat_engine import ThreatEngine
from monitor.usb_monitor import (
    start_usb_monitor,
    stop_usb_monitor
)

# =========================================================
# Logging Configuration
# =========================================================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s"
)

logger = logging.getLogger("ATLAS-Main")


# =========================================================
# Initialize Threat Engine
# =========================================================

engine = ThreatEngine()

event_bus.subscribe(
    engine.process_event
)

logger.info(
    "Threat Engine Connected To Event Bus"
)


# =========================================================
# Start Monitoring Services
# =========================================================

start_monitor()

start_process_monitor()
start_usb_monitor()

logger.info(
    "All Monitoring Services Started"
)


# =========================================================
# Main Runtime Loop
# =========================================================

try:

    logger.info("ATLAS Started")

    while True:
        sleep(1)

except KeyboardInterrupt:

    logger.info(
        "Shutdown Signal Received"
    )

    stop_monitor()
    stop_usb_monitor()
    stop_process_monitor()

    logger.info(
        "All Monitoring Services Stopped"
    )

    logger.info("ATLAS Stopped")

except Exception as error:

    logger.exception(
        "Fatal ATLAS Error: %s",
        error
    )

    stop_monitor()

    stop_process_monitor()