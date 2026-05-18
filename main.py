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
from notifications import (
    notification_manager
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

TRAINING_HISTORY_SAVE_INTERVAL_SECONDS = 300

parser.add_argument(
    "--train",
    action="store_true",
    help="Train ML baseline model"
)

parser.add_argument(
    "--train-days",
    type=float,
    default=1.0,
    help="Days to collect baseline telemetry before training"
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

if not ml_detector.is_trained:
    logger.warning(
        "ML scoring inactive � no calibrated model found. "
        "Rule-based detection is active. "
        "Run py -3.10 main.py --train to calibrate."
    )
else:
    logger.info(
        "ML scoring active � thresholds calibrated for this machine."
    )


def _initial_training_watcher():
    logger.info(
        "Initial training mode � collecting 4hr baseline � 1440 samples silently. "
        "Rule-based detection is active."
    )
    while len(feature_extractor.feature_history) < 1440:
        time.sleep(60)
    logger.info("4hr baseline reached � training initial model.")
    ml_detector.train()
    ml_detector.save_history()
    logger.info("Initial model trained and saved.")


if not ml_detector.is_initial_training_complete and not args.train:
    threading.Thread(
        target=_initial_training_watcher,
        daemon=True
    ).start()

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

if not args.train:
    ml_thread.start()

logger.info(
    "All Monitoring Services Started"
)


# =========================================================
# Main Runtime Loop
# =========================================================

try:

    if args.train:
        logger.info("ATLAS Started � ML Training Mode (%.1f days)", args.train_days)
    elif not ml_detector.is_initial_training_complete:
        logger.info(
            "ATLAS Started � collecting initial 4hr baseline � 1440 samples. "
            "Rule-based detection active. %d vectors loaded from previous run.",
            len(feature_extractor.feature_history)
        )
    else:
        logger.info("ATLAS Started � ML model loaded and active.")

    if args.train:

        logger.info(
        "ML Training Mode Started"
    )

        logger.info(
        "Collecting baseline telemetry for %.2f days...",
        args.train_days
    )

        training_started = time.time()
        last_history_save = training_started
        training_duration_seconds = (
            args.train_days
            * 24
            * 60
            * 60
        )

        while (
            time.time() - training_started
            < training_duration_seconds
        ):

            log_memory_usage()

            if (
                time.time() - last_history_save
                >= TRAINING_HISTORY_SAVE_INTERVAL_SECONDS
            ):
                ml_detector.save_history()
                last_history_save = time.time()

            sleep(5)

        ml_detector.train()

        logger.info(
        "Training Complete"
    )

        exit()
    while True:

        log_memory_usage()

        sleep(5)
except KeyboardInterrupt:
    logger.info("Shutdown Signal Received")

    if args.train:
        sample_count = len(feature_extractor.feature_history)
        if sample_count < 60:
            logger.warning(
                "Only %d samples collected � minimum is 60. "
                "Skipping training. History saved for next run.",
                sample_count
            )
        else:
            logger.info(
                "Training interrupted � %d samples collected. "
                "Training model now.",
                sample_count
            )
            ml_detector.train()

    ml_detector.save_history()
    stop_monitor()
    stop_usb_monitor()
    stop_process_monitor()
    logger.info("All Monitoring Services Stopped")
    logger.info("ATLAS Stopped")

except Exception as error:

    logger.exception(
        "Fatal ATLAS Error: %s",
        error
    )

    ml_detector.save_history()

    stop_monitor()

    stop_usb_monitor()

    stop_process_monitor()
