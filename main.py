"""
ATLAS Main Launcher

Initializes:
- Threat Engine
- File Monitor
- Process Monitor
- Event Bus Connections
"""
from dotenv import load_dotenv
import argparse
import logging
import os
import threading
import time
import requests
from time import sleep
from monitor.response_engine import response_engine
from config.logging_config import get_logger

load_dotenv()

import subprocess # Added missing import
import psutil
import schedule

from core.runtime_state import runtime_state
from core.runtime_sync import runtime_sync
from core.training_state import load_training_state
from core.vault import is_locked as is_vault_locked
from database.client import supabase
from monitor.event_bus import event_bus
from monitor.feature_extractor import feature_extractor
from monitor.file_monitor import start_monitor, stop_monitor
from monitor.ml_detector import ml_detector
from monitor.network_monitor import network_monitor
from monitor.process_monitor import start_process_monitor, stop_process_monitor
from monitor.threat_engine import ThreatEngine
from monitor.usb_monitor import start_usb_monitor, stop_usb_monitor
from notifications import notification_manager


# =========================================================
# Logging Configuration
# =========================================================
def run_scheduler():
    runtime_state.update(scheduler_status="online")
    while True:
        schedule.run_pending()
        time.sleep(1)


def runtime_health_loop():
    while True:
        try:
            supabase.table("auth").select("email").limit(1).execute()
            runtime_state.update(supabase_status="online")
        except Exception:
            runtime_state.update(supabase_status="offline")
        time.sleep(30)


def launch_dashboard():
    try:
        from dashboard.app import main as dashboard_main
    except Exception as error:
        logger.warning("Dashboard unavailable: %s", error)
        return False

    try:
        os.environ["ATLAS_EMBEDDED_RUNTIME"] = "1"
        logger.info("Dashboard started")
        runtime_state.update(dashboard_status="online")
        dashboard_main()
        return True
    except Exception as error:
        logger.exception("Dashboard failed to start: %s", error)
        runtime_state.update(dashboard_status="failed")
        return False


def launch_flask_api():
    try:
        from api.flask_app import app as flask_app
    except Exception as error:
        logger.warning("Flask API unavailable: %s", error)
        return

    def _run_api():
        try:
            logger.info("Flask bind address configured: 0.0.0.0:80")
            flask_app.run(host="0.0.0.0", port=80, debug=False, use_reloader=False)
        except Exception as error:
            logger.exception("Flask API failed: %s", error)

    try:
        threading.Thread(target=_run_api, daemon=True).start()
        logger.info("Flask API started")
        runtime_state.update(api_status="online")
    except Exception as error:
        logger.exception("Flask API thread failed to start: %s", error)
        runtime_state.update(api_status="failed")


def start_ngrok():
    """Starts the ngrok tunnel in the background if NGROK_DOMAIN is set."""
    ngrok_domain = os.getenv("NGROK_DOMAIN")
    if not ngrok_domain:
        logger.info("NGROK_DOMAIN not set in .env, skipping ngrok auto-start. Biometric QR flow will start it on demand if needed.")
        return

    try:
        logger.info("Attempting to auto-start ngrok tunnel for domain: %s", ngrok_domain)
        command = ["ngrok", "http", "80", "--domain", ngrok_domain]

        subprocess.Popen(
            command,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        time.sleep(2)

        response = requests.get("http://127.0.0.1:4040/api/tunnels", timeout=5)
        response.raise_for_status()
        data = response.json()

        public_url = None
        for tunnel in data.get("tunnels", []):
            if tunnel.get("proto") == "https":
                public_url = tunnel.get("public_url")
                break

        if public_url:
            logger.info("ngrok tunnel established at: %s", public_url)
            runtime_state.set_nested("biometric_state", {"base_auth_url": public_url})
        else:
            logger.warning("ngrok started, but could not retrieve public URL from API.")

    except FileNotFoundError:
        logger.warning("ngrok executable not found in PATH. Biometric QR flow may fail. Please install ngrok.")
    except Exception as e:
        logger.error("Failed to start or query ngrok tunnel: %s. Biometric QR flow may fail.", e)


logger = get_logger("ATLAS-Main")

parser = argparse.ArgumentParser()
runtime_state.update(vault_locked=is_vault_locked())

TRAINING_HISTORY_SAVE_INTERVAL_SECONDS = 300

parser.add_argument(
    "--train",
    action="store_true",
    help="Train ML baseline model",
)

parser.add_argument(
    "--train-days",
    type=float,
    default=1.0,
    help="Days to collect baseline telemetry before training",
)

parser.add_argument(
    "--baseline-train",
    action="store_true",
    help="Run lightweight baseline telemetry collection (separate from normal runtime)",
)

args = parser.parse_args()


## Startup functions to separate normal vs baseline training runtimes

def start_full_runtime():
    """Start the full ATLAS runtime stack (production/demo mode)."""
    # Start ngrok at the beginning of the full runtime startup
    start_ngrok()

    # Initialize core systems that should NOT run in training mode
    engine = ThreatEngine()
    event_bus.subscribe(engine.process_event)
    logger.info("Threat Engine Connected To Event Bus")

    _ = response_engine
    logger.info("Response Engine Connected To Event Bus")

    _ = runtime_sync
    runtime_state.update(response_engine_subscribed=True)

    # ML lifecycle: load model + history and schedule regular retraining & history saves
    ml_detector.load_model()
    ml_detector.load_history()

    if not ml_detector.is_trained:
        logger.warning(
            "ML scoring inactive - no calibrated model found. "
            "Rule-based detection is active. "
            "Run py -3.10 main.py --baseline-train --train-days X to collect baseline."
        )
    else:
        logger.info("ML scoring active - thresholds calibrated for this machine.")

    runtime_state.set_nested(
        "ml_status",
        {
            "trained": ml_detector.is_trained,
            "initial_training_complete": ml_detector.is_initial_training_complete,
            "critical_threshold": ml_detector.critical_threshold,
            "high_threshold": ml_detector.high_threshold,
            "medium_threshold": ml_detector.medium_threshold,
        },
    )

    training_state_snapshot = load_training_state()
    if training_state_snapshot:
        runtime_state.set_nested(
            "ml_status",
            {
                "initial_training_complete": bool(training_state_snapshot.get("is_initial_training_complete", False)),
                "critical_threshold": training_state_snapshot.get("critical_threshold"),
                "high_threshold": training_state_snapshot.get("high_threshold"),
                "medium_threshold": training_state_snapshot.get("medium_threshold"),
            },
        )

    # Start scheduler and health loop
    ml_detector.schedule_retraining()
    scheduler_thread = threading.Thread(target=run_scheduler, daemon=True)
    scheduler_thread.start()
    threading.Thread(target=runtime_health_loop, daemon=True).start()

    # Start all monitoring services (full runtime)
    start_monitor()
    start_process_monitor()
    start_usb_monitor()
    network_thread = threading.Thread(target=network_monitor.start, daemon=True)
    network_thread.start()
    runtime_state.set_nested(
        "monitor_states",
        {
            "file_monitor": True,
            "process_monitor": True,
            "usb_monitor": True,
            "network_monitor": True,
        },
    )

    feature_thread = threading.Thread(target=feature_extractor.start, daemon=True)
    feature_thread.start()
    runtime_state.set_nested("monitor_states", {"feature_extractor": True})

    ml_thread = threading.Thread(target=ml_detector.start_monitoring, daemon=True)
    ml_thread.start()

    logger.info("All Monitoring Services Started (full runtime)")

    # Start UI/API
    launch_flask_api()


def start_training_runtime(train_days: float):
    """Start the lightweight baseline telemetry collection runtime.

    This environment intentionally avoids any active/intrusive subsystems
    (response engine, dashboard, API, containment, alerts, simulator).
    """
    runtime_state.update(training_mode=True)

    # User-facing banner
    banner = (
        "\nATLAS BASELINE TRAINING MODE\n"
        "Telemetry collection only\n"
        "Containment disabled\n"
        "Response engine disabled\n"
        "Dashboard disabled\n"
        "Collecting behavioral baseline...\n"
    )
    print(banner)
    logger.info("Starting baseline training for %.2f days", train_days)

    # ML: only load history (preserve partial baseline); DO NOT enable scoring or scheduled retrains
    ml_detector.load_history()

    # Start only lightweight monitors needed for baseline telemetry
    start_monitor()
    start_process_monitor()
    # Keep network monitoring for training
    network_thread = threading.Thread(target=network_monitor.start, daemon=True)
    network_thread.start()

    runtime_state.set_nested(
        "monitor_states",
        {
            "file_monitor": True,
            "process_monitor": True,
            "network_monitor": True,
        },
    )

    feature_thread = threading.Thread(target=feature_extractor.start, daemon=True)
    feature_thread.start()
    runtime_state.set_nested("monitor_states", {"feature_extractor": True})

    logger.info("Baseline monitoring started (collection-only)")


# =========================================================
# Main Runtime Loop (branched)
# =========================================================
baseline_mode = args.baseline_train or args.train

try:
    if baseline_mode:
        # Training-only runtime
        start_training_runtime(args.train_days)
        logger.info("ATLAS Started - BASELINE TRAINING MODE (%.1f days)", args.train_days)
        logger.info("Collecting baseline telemetry for %.2f days...", args.train_days)

        training_started = time.time()
        last_history_save = training_started
        last_checkpoint = training_started
        training_duration_seconds = args.train_days * 24 * 60 * 60
        CHECKPOINT_INTERVAL_SECONDS = TRAINING_HISTORY_SAVE_INTERVAL_SECONDS * 2

        while time.time() - training_started < training_duration_seconds:
            if time.time() - last_history_save >= TRAINING_HISTORY_SAVE_INTERVAL_SECONDS:
                ml_detector.save_history()
                last_history_save = time.time()

            if time.time() - last_checkpoint >= CHECKPOINT_INTERVAL_SECONDS:
                try:
                    ml_detector.save_model()
                    logger.info("ML checkpoint saved (training mode)")
                except Exception:
                    logger.warning("Failed to save ML checkpoint")
                last_checkpoint = time.time()

            sleep(5)

        # Final training step after collection
        logger.info("Baseline collection complete - training model now.")
        ml_detector.train()
        logger.info("Training Complete")
        exit()

    else:
        # Full runtime
        start_full_runtime()
        logger.info("ATLAS Started - full runtime")

        # The dashboard GUI must run on the main thread. This call is blocking
        # and will only return when the user closes the UI window. All other
        # services are running in daemon threads in the background.
        if not launch_dashboard():
            logger.error("Dashboard failed to launch. ATLAS running in headless mode.")
            while True:
                sleep(5)

except KeyboardInterrupt:
    logger.info("Shutdown Signal Received")

    if baseline_mode:
        sample_count = len(feature_extractor.feature_history)
        if sample_count < 60:
            logger.warning(
                "Only %d samples collected - minimum is 60. "
                "Skipping training. History saved for next run.",
                sample_count,
            )
        else:
            logger.info(
                "Training interrupted - %d samples collected. Training model now.",
                sample_count,
            )
            ml_detector.train()

    # Always persist collected history and gracefully stop monitors
    ml_detector.save_history()
    try:
        stop_monitor()
    except Exception:
        pass
    try:
        stop_usb_monitor()
    except Exception:
        pass
    try:
        stop_process_monitor()
    except Exception:
        pass
    try:
        network_monitor.stop()
    except Exception:
        pass

    runtime_state.set_nested(
        "monitor_states",
        {
            "file_monitor": False,
            "process_monitor": False,
            "usb_monitor": False,
            "feature_extractor": False,
            "network_monitor": False,
        },
    )
    runtime_state.update(
        scheduler_status="offline",
        api_status="offline",
        dashboard_status="offline",
    )
    logger.info("All Monitoring Services Stopped")
    logger.info("ATLAS Stopped")

except Exception as error:
    logger.exception("Fatal ATLAS Error: %s", error)
    try:
        ml_detector.save_history()
    except Exception:
        pass
    try:
        stop_monitor()
    except Exception:
        pass
    try:
        stop_usb_monitor()
    except Exception:
        pass
    try:
        stop_process_monitor()
    except Exception:
        pass
    try:
        network_monitor.stop()
    except Exception:
        pass
    runtime_state.set_nested(
        "monitor_states",
        {
            "file_monitor": False,
            "process_monitor": False,
            "usb_monitor": False,
            "feature_extractor": False,
            "network_monitor": False,
        },
    )
