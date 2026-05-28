"""
ATLAS Feature Extractor

Collects behavioral telemetry every
10 seconds and converts it into
ML-ready feature vectors.

FIXES APPLIED:
  1. Added window_seconds time filter —
     only counts events from the last 10s,
     not the entire deque history.
  2. window_processes resets each sample
     so new_processes is accurate per window,
     not lifetime-cumulative.
  3. Every event published by external
     monitors must include "timestamp":
     time.time() — see note at bottom.
"""

import threading
import time
from collections import deque
from datetime import datetime
from typing import Dict, List

import psutil
from config.logging_config import get_logger
from monitor.event_bus import event_bus

logger = get_logger("ml")

class FeatureExtractor:

    def __init__(self):
        self.window_seconds = 10

        self.event_window = deque(
            maxlen=500
        )

        self.feature_history = deque(
            maxlen=50000
        )

        self._stop_event = (
            threading.Event()
        )

        event_bus.subscribe(
            self.process_event
        )

    def process_event(
        self,
        event: Dict
    ) -> None:

        # ── FIX 1 ───────────────────────
        # Stamp every inbound event with
        # the current time so the window
        # filter works correctly.
        # External monitors should also
        # include "timestamp": time.time()
        # in every event they publish —
        # this is a safety net for any
        # that don't.
        if "timestamp" not in event:
            event["timestamp"] = time.time()
        # ────────────────────────────────

        self.event_window.append(event)

    def build_feature_vector(
        self
    ) -> List[float]:

        # ── FIX 1 ───────────────────────
        # Compute current time once
        # so all comparisons are consistent.
        current_time = time.time()
        # ────────────────────────────────

        files_modified = 0
        files_deleted = 0
        files_renamed = 0
        outbound_connections = 0
        failed_auth_attempts = 0
        unique_suspicious_ips = set()

        # ── FIX 2 ───────────────────────
        # Use a per-call set so
        # new_processes reflects activity
        # in THIS 10-second window only,
        # not all processes ever seen.
        window_processes = set()
        # ────────────────────────────────

        for event in self.event_window:

            # ── FIX 1 ───────────────────
            # Skip events older than the
            # window. Without this every
            # event ever seen is counted,
            # making counts grow forever
            # and confusing the model.
            event_age = current_time - event["timestamp"]

            if event_age > self.window_seconds:
                continue
            # ────────────────────────────

            event_type = event.get(
                "event_type", ""
            )

            if event_type == "FILE_MODIFIED":
                files_modified += 1

            elif event_type == "FILE_DELETED":
                files_deleted += 1

            elif event_type == "FILE_RENAMED":
                files_renamed += 1

            elif event_type == "PROCESS_DETECTED":
                # ── FIX 2 ───────────────
                # Add to the window-local
                # set, not a lifetime set.
                window_processes.add(
                    event.get(
                        "process_name",
                        "UNKNOWN"
                    )
                )
                # ────────────────────────

            elif event_type == "NETWORK_CONNECTION":
                # Count only suspicious network activity for ML signal stability.
                # Normal browser bursts should not dominate anomaly scoring.
                if bool(event.get("suspicious")) and bool(event.get("risk_reasons")):
                    remote_ip = event.get("remote_ip")
                    if remote_ip:
                        unique_suspicious_ips.add(str(remote_ip))
                    else:
                        outbound_connections += 1

            elif event_type == "AUTH_FAIL":
                failed_auth_attempts += 1

        # ── FIX 2 ───────────────────────
        # Count of DISTINCT new processes
        # seen in this 10-second window.
        new_processes = len(window_processes)
        outbound_connections += min(len(unique_suspicious_ips), 3)
        # ────────────────────────────────

        cpu_percent = psutil.cpu_percent()

        now = datetime.now()

        feature_vector = [
            files_modified,         # 0
            files_deleted,          # 1
            files_renamed,          # 2
            new_processes,          # 3  ← now per-window, not lifetime
            cpu_percent,            # 4
            outbound_connections,   # 5
            failed_auth_attempts,    # 6
            now.hour,               # 7
            now.weekday(),          # 8
        ]

        self.feature_history.append(
            feature_vector
        )

        logger.debug(
            "Feature Vector Built: %s",
            feature_vector
        )

        return feature_vector

    def start(self) -> None:

        logger.info(
            "Feature Extractor Started"
        )

        while not self._stop_event.is_set():
            self.build_feature_vector()
            time.sleep(self.window_seconds)

    def stop(self) -> None:

        self._stop_event.set()

        logger.info(
            "Feature Extractor Stopped"
        )


feature_extractor = FeatureExtractor()


# ════════════════════════════════════════
# IMPORTANT — ALL MONITORS MUST DO THIS:
#
# Every event published to event_bus
# must include a "timestamp" key:
#
#   event_bus.publish({
#       "type":      "FILE_MODIFIED",
#       "path":      path,
#       "timestamp": time.time(),   ← required
#   })
#
# Without it the window filter above
# defaults to timestamp=0 which means
# the event is always treated as ancient
# and skipped, giving you all-zero vectors.
# ════════════════════════════════════════
