"""
ATLAS Main Launcher

Initializes:
- Threat Engine
- File Monitor
- Process Monitor
- Event Bus Connections
"""
import threading
import psutil
import os
import logging
from time import sleep
import argparse
import time
import schedule
from monitor.feature_extractor import (
    feature_extractor
)

from monitor.ml_detector import (
    ml_detector
)
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
def log_memory_usage():

    process = psutil.Process(
        os.getpid()
    )

    memory_mb = (
        process.memory_info().rss
        / 1024
        / 1024
    )

    logger.info(
        "ATLAS Memory Usage: %.2f MB",
        memory_mb
    )


def run_scheduler():

    while True:

        schedule.run_pending()

        time.sleep(1)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s"
)

logger = logging.getLogger("ATLAS-Main")
parser = argparse.ArgumentParser()

parser.add_argument(
    "--train",
    action="store_true",
    help="Train ML baseline model"
)

args = parser.parse_args()

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
# Initialize ML Lifecycle
# =========================================================

ml_detector.load_model()
ml_detector.load_history()
ml_detector.schedule_retraining()

scheduler_thread = threading.Thread(
    target=run_scheduler,
    daemon=True
)

scheduler_thread.start()


# =========================================================
# Start Monitoring Services
# =========================================================

start_monitor()

start_process_monitor()
start_usb_monitor()
feature_thread = threading.Thread(
    target=feature_extractor.start,
    daemon=True
)

feature_thread.start()

ml_thread = threading.Thread(
    target=ml_detector.start_monitoring,
    daemon=True
)

ml_thread.start()

logger.info(
    "All Monitoring Services Started"
)


# =========================================================
# Main Runtime Loop
# =========================================================

try:

    logger.info("ATLAS Started")
    if args.train:

        logger.info(
        "ML Training Mode Started"
    )

        logger.info(
        "Collecting baseline telemetry..."
    )

        time.sleep(600)

        ml_detector.train()

        logger.info(
        "Training Complete"
    )

        exit()
    while True:

        log_memory_usage()

        sleep(5)
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
