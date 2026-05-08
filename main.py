"""
ATLAS Main Launcher
"""

from monitor.threat_engine import ThreatEngine
from monitor.file_monitor import (
    start_monitor,
    stop_monitor
)
from monitor.process_monitor import (
    start_process_monitor,
    stop_process_monitor
)
from monitor.event_bus import event_bus

import logging
from time import sleep


# =========================================================
# Logging
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

# Subscribe engine to event bus
event_bus.subscribe(engine.process_event)

logger.info(
    "Threat Engine Connected To Event Bus"
)

# Start monitoring
start_monitor()
start_process_monitor()

try:

    logger.info("ATLAS Started")

    while True:
        sleep(1)

except KeyboardInterrupt:

    stop_monitor()
    stop_process_monitor()

    logger.info("ATLAS Stopped")
