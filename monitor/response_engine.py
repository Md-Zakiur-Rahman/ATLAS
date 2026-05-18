"""
ATLAS Response Engine

Automated threat response and
containment system.

FIXES APPLIED (Day 6):
  1. ML_ANOMALY now handled in its own
     block with an early return - previously
     it fell through to pid-based handlers
     which immediately returned because
     ML events have no pid, so HIGH ML
     anomalies were silently dropped.
  2. handle_ml_critical and handle_ml_high
     added - vault lock and alert published
     even without a pid to kill.
  3. Rollback log line moved inside the
     ransomware_detected block - was always
     logging "Automatic Rollback Triggered"
     even when no rollback happened.
  4. VAULT_LOCKED event published at end
     of handle_critical_threat - previously
     a non-brute-force critical (ransomware)
     killed the process and rolled back but
     never locked the vault.
  5. timestamp added to all published events
     so feature_extractor window filter works.
"""

import time
import logging
import os
import socket
import uuid

import psutil

from database.client import supabase
from monitor.rename_log import rename_log
from monitor.event_bus import event_bus
from notifications.email_sender import email_sender

logging.basicConfig(
    level=logging.INFO,
    format=(
        "%(asctime)s | "
        "%(levelname)s | "
        "%(message)s"
    )
)

logger = logging.getLogger(
    "ATLAS-ResponseEngine"
)


class ResponseEngine:

    def __init__(self):

        event_bus.subscribe(
            self.process_event
        )

    def process_event(
        self,
        event
    ) -> None:

        event_type = event.get("type", "")
        severity   = event.get("severity", "")

        if event_type == "VAULT_LOCKED":
            logger.info("VAULT_LOCKED event observed; no further escalation needed.")
            return

        # AUTH_BRUTE_FORCE - handle and
        # return early, unchanged from
        # original.
        if event_type == "AUTH_BRUTE_FORCE":
            self.handle_auth_bruteforce(event)
            return

        # ML_ANOMALY now has its own block
        # with an early return.
        #
        # Previously the code logged a
        # warning then fell through to the
        # severity checks below. Those
        # checks called handle_high_threat
        # which immediately returned because
        # ML events carry no pid and no
        # suspicious flag - so HIGH and
        # CRITICAL ML anomalies did nothing.
        if event_type == "ML_ANOMALY":

            score    = event.get("score", 0)
            severity = event.get("severity", "LOW")

            logger.warning(
                "ML Anomaly | Score: %.4f | Severity: %s",
                score,
                severity,
            )

            if severity == "CRITICAL":
                self.handle_ml_critical(event)

            elif severity == "HIGH":
                self.handle_ml_high(event)

            elif severity == "MEDIUM":
                self.handle_medium_threat(event)

            # Early return - do NOT fall
            # through to pid-based handlers.
            return

        # Network suspicious connection -
        # unchanged from original.
        if event_type == "NETWORK_CONNECTION":
            if event.get("suspicious"):
                self.handle_high_threat(event)

        # Generic severity routing for all
        # other event types.
        if severity == "CRITICAL":
            self.handle_critical_threat(event)

        elif severity == "HIGH":
            self.handle_high_threat(event)

        elif severity == "MEDIUM":
            self.handle_medium_threat(event)

    def _capture_screenshot(self) -> str:
        try:
            from PIL import ImageGrab
            os.makedirs("assets", exist_ok=True)
            path = "assets/incident.png"
            ImageGrab.grab().save(path)
            logger.info("Screenshot captured: %s", path)
            return path
        except Exception as error:
            logger.warning("Screenshot failed: %s", error)
            return None

    # =====================================
    # MEDIUM
    # =====================================
    def handle_medium_threat(
        self,
        event
    ) -> None:

        logger.warning(
            "Medium Threat Logged: %s",
            event
        )

        email_sender.send_medium_alert(event)

    # =====================================
    # HIGH - pid-based (process monitor)
    # =====================================
    def handle_high_threat(
        self,
        event
    ) -> None:

        pid = event.get("pid")

        if not pid or not event.get("suspicious"):
            return

        try:
            process = psutil.Process(pid)
            process.kill()

            logger.warning(
                "Suspicious Process Terminated: PID %s",
                pid
            )

            email_sender.send_high_alert(event)

        except Exception as error:
            logger.error(
                "Process Termination Failed: %s",
                error
            )

    # Handles HIGH severity ML anomaly.
    # No pid to kill - raises an alert
    # event so the dashboard can surface it.
    def handle_ml_high(
        self,
        event
    ) -> None:

        logger.warning(
            "ML HIGH Anomaly - elevated monitoring active"
        )

        event_bus.publish({
            "type":      "ML_HIGH_ALERT",
            "score":     event.get("score"),
            "severity":  "HIGH",
            "timestamp": time.time(),
        })

        email_sender.send_high_alert(event)

    # Handles CRITICAL severity ML anomaly.
    # No pid available so we lock the vault
    # as a precautionary containment step.
    def handle_ml_critical(
        self,
        event
    ) -> None:

        logger.critical(
            "ML CRITICAL Anomaly - locking vault as precaution"
        )

        event_bus.publish({
            "type":      "VAULT_LOCKED",
            "reason":    "ML anomaly score CRITICAL",
            "severity":  "CRITICAL",
            "timestamp": time.time(),
        })

        screenshot_path = self._capture_screenshot()
        email_sender.send_critical_alert(event, screenshot_path)

    # =====================================
    # CRITICAL - process-based
    # =====================================
    def handle_critical_threat(
        self,
        event
    ) -> None:

        logger.critical("Critical Threat Detected")

        pid = event.get("pid")

        if pid:
            try:
                psutil.Process(pid).kill()

                logger.critical(
                    "Critical Process Killed: PID %s",
                    pid
                )

            except Exception as error:
                logger.error(
                    "Critical Kill Failed: %s",
                    error
                )

        # Rollback log moved inside the if
        # block. Previously it always logged
        # "Automatic Rollback Triggered"
        # even when ransomware_detected was
        # False and no rollback happened.
        if event.get("ransomware_detected"):
            rename_log.rollback()

            logger.critical(
                "Automatic Rollback Triggered"
            )

            email_sender.send_block_confirm(
                files_restored=rename_log.last_rollback_count,
                attacker_ip=event.get("attacker_ip"),
            )

        else:
            logger.critical(
                "Critical threat handled - no rollback needed"
            )

        # Vault lock now fires on ALL
        # critical threats, not just brute
        # force. Previously a ransomware
        # critical would kill the process
        # and rollback files but leave the
        # vault wide open.
        event_bus.publish({
            "type":      "VAULT_LOCKED",
            "reason":    event.get("type", "CRITICAL_THREAT"),
            "severity":  "CRITICAL",
            "timestamp": time.time(),
        })

        screenshot_path = self._capture_screenshot()
        email_sender.send_critical_alert(event, screenshot_path)
        if event.get("attacker_ip"):
            logger.warning("Attacker IP flagged: %s", event.get("attacker_ip"))
            from monitor.network_monitor import network_monitor
            network_monitor.blacklist_ip(event.get("attacker_ip"))

    # =====================================
    # AUTH BRUTE FORCE
    # Unchanged from original except:
    # FIX 5 - timestamp added to
    # VAULT_LOCKED publish.
    # =====================================
    def handle_auth_bruteforce(
        self,
        event
    ) -> None:

        email = event.get("email")

        if not email:
            return

        try:
            supabase.table("auth").update(
                {"vault_locked": True}
            ).eq("email", email).execute()

            logger.critical(
                "Vault locked for %s",
                email
            )

            event_bus.publish({
                "type":      "VAULT_LOCKED",
                "email":     email,
                "severity":  "CRITICAL",
                "timestamp": time.time(),
            })

            email_sender.send_critical_alert(event)

        except Exception as error:
            logger.error(
                "Vault lock failed: %s",
                error
            )


response_engine = ResponseEngine()
