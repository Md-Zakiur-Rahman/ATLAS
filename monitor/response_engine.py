"""
ATLAS Response Engine

Automated threat response and
containment system.

FIXES APPLIED (Day 6):
  1. ML_ANOMALY now handled in its own
     block with an early return — previously
     it fell through to pid-based handlers
     which immediately returned because
     ML events have no pid, so HIGH ML
     anomalies were silently dropped.
  2. handle_ml_critical and handle_ml_high
     added — vault lock and alert published
     even without a pid to kill.
  3. Rollback log line moved inside the
     ransomware_detected block — was always
     logging "Automatic Rollback Triggered"
     even when no rollback happened.
  4. VAULT_LOCKED event published at end
     of handle_critical_threat — previously
     a non-brute-force critical (ransomware)
     killed the process and rolled back but
     never locked the vault.
  5. timestamp added to all published events
     so feature_extractor window filter works.

DAY 8 TODOs marked with: # ── TODO D8 ──
  - Telegram alert on every CRITICAL/HIGH
  - send_block_confirm after rollback
  - IP blacklist enforcement
  - Screenshot capture on CRITICAL
  - Remote lock token generation
"""

import time
import logging

import psutil

from database.client import supabase
from monitor.rename_log import rename_log
from monitor.event_bus import event_bus

# ── TODO D8 ─────────────────────────────
# from notifications.telegram_bot import telegram_bot
# Uncomment once telegram_bot.py is built.
# ────────────────────────────────────────

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

        # ── FIX 1 ───────────────────────
        # AUTH_BRUTE_FORCE — handle and
        # return early, unchanged from
        # original.
        # ────────────────────────────────
        if event_type == "AUTH_BRUTE_FORCE":
            self.handle_auth_bruteforce(event)
            return

        # ── FIX 1 ───────────────────────
        # ML_ANOMALY now has its own block
        # with an early return.
        #
        # Previously the code logged a
        # warning then fell through to the
        # severity checks below. Those
        # checks called handle_high_threat
        # which immediately returned because
        # ML events carry no pid and no
        # suspicious flag — so HIGH and
        # CRITICAL ML anomalies did nothing.
        # ────────────────────────────────
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

            # Early return — do NOT fall
            # through to pid-based handlers.
            return

        # Network suspicious connection —
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

    # ────────────────────────────────────
    # MEDIUM
    # ────────────────────────────────────
    def handle_medium_threat(
        self,
        event
    ) -> None:

        logger.warning(
            "Medium Threat Logged: %s",
            event
        )

        # ── TODO D8 ─────────────────────
        # No Telegram on MEDIUM —
        # dashboard log only. But on Day 8
        # you can optionally surface this
        # in the dashboard alert feed:
        #
        # event_bus.publish({
        #     "type":      "DASHBOARD_ALERT",
        #     "severity":  "MEDIUM",
        #     "message":   str(event),
        #     "timestamp": time.time(),
        # })
        # ────────────────────────────────

    # ────────────────────────────────────
    # HIGH — pid-based (process monitor)
    # ────────────────────────────────────
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

            # ── TODO D8 ─────────────────
            # telegram_bot.send_alert(
            #     f"⚠️ HIGH Threat\n"
            #     f"Suspicious process killed\n"
            #     f"PID: {pid}"
            # )
            # ────────────────────────────

        except Exception as error:
            logger.error(
                "Process Termination Failed: %s",
                error
            )

    # ── FIX 1 (new method) ──────────────
    # Handles HIGH severity ML anomaly.
    # No pid to kill — raises an alert
    # event so the dashboard and (Day 8)
    # Telegram can surface it.
    # ────────────────────────────────────
    def handle_ml_high(
        self,
        event
    ) -> None:

        logger.warning(
            "ML HIGH Anomaly — elevated monitoring active"
        )

        event_bus.publish({
            "type":      "ML_HIGH_ALERT",
            "score":     event.get("score"),
            "severity":  "HIGH",
            "timestamp": time.time(),
        })

        # ── TODO D8 ─────────────────────
        # telegram_bot.send_alert(
        #     f"⚠️ HIGH ML Anomaly\n"
        #     f"Score: {event.get('score', 'N/A'):.4f}\n"
        #     f"System is monitoring closely."
        # )
        # ────────────────────────────────

    # ── FIX 1 (new method) ──────────────
    # Handles CRITICAL severity ML anomaly.
    # No pid available so we lock the vault
    # as a precautionary containment step.
    # ────────────────────────────────────
    def handle_ml_critical(
        self,
        event
    ) -> None:

        logger.critical(
            "ML CRITICAL Anomaly — locking vault as precaution"
        )

        event_bus.publish({
            "type":      "VAULT_LOCKED",
            "reason":    "ML anomaly score CRITICAL",
            "severity":  "CRITICAL",
            "timestamp": time.time(),
        })

        # ── TODO D8 ─────────────────────
        # telegram_bot.send_alert(
        #     f"🚨 CRITICAL ML Anomaly\n"
        #     f"Score: {event.get('score', 'N/A'):.4f}\n"
        #     f"Vault locked as precaution.\n"
        #     f"Review dashboard immediately."
        # )
        # ────────────────────────────────

    # ────────────────────────────────────
    # CRITICAL — process-based
    # ────────────────────────────────────
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

        # ── FIX 3 ───────────────────────
        # Rollback log moved inside the if
        # block. Previously it always logged
        # "Automatic Rollback Triggered"
        # even when ransomware_detected was
        # False and no rollback happened.
        # ────────────────────────────────
        if event.get("ransomware_detected"):
            rename_log.rollback()

            logger.critical(
                "Automatic Rollback Triggered"
            )

            # ── TODO D8 ─────────────────
            # telegram_bot.send_block_confirm(
            #     files_restored=rename_log.last_rollback_count,
            #     attacker_ip=event.get("attacker_ip"),
            # )
            # ────────────────────────────

        else:
            logger.critical(
                "Critical threat handled — no rollback needed"
            )

        # ── FIX 4 ───────────────────────
        # Vault lock now fires on ALL
        # critical threats, not just brute
        # force. Previously a ransomware
        # critical would kill the process
        # and rollback files but leave the
        # vault wide open.
        # ────────────────────────────────
        event_bus.publish({
            "type":      "VAULT_LOCKED",
            "reason":    event.get("type", "CRITICAL_THREAT"),
            "severity":  "CRITICAL",
            "timestamp": time.time(),
        })

        # ── TODO D8 ─────────────────────
        # On Day 8 add here:
        #
        # 1. Screenshot capture
        #    from PIL import ImageGrab
        #    screenshot = ImageGrab.grab()
        #    screenshot.save("assets/incident.png")
        #    telegram_bot.send_photo("assets/incident.png")
        #
        # 2. One-time remote lock token
        #    token = generate_one_time_token()
        #    lock_url = f"http://{LOCAL_IP}:5000/remote-lock?token={token}"
        #    telegram_bot.send_alert(
        #        f"🚨 CRITICAL THREAT\n"
        #        f"Type: {event.get('type')}\n"
        #        f"Vault locked automatically.\n"
        #        f"Confirm: {lock_url}"
        #    )
        #
        # 3. IP blacklist
        #    if event.get("attacker_ip"):
        #        ip_blacklist.add(event["attacker_ip"])
        # ────────────────────────────────

    # ────────────────────────────────────
    # AUTH BRUTE FORCE
    # Unchanged from original except:
    # ── FIX 5 — timestamp added to
    # VAULT_LOCKED publish.
    # ────────────────────────────────────
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
                "timestamp": time.time(),   # ── FIX 5
            })

            # ── TODO D8 ─────────────────
            # telegram_bot.send_alert(
            #     f"🚨 BRUTE FORCE DETECTED\n"
            #     f"Account: {email}\n"
            #     f"Vault locked.\n"
            #     f"OTP required to unlock."
            # )
            # ────────────────────────────

        except Exception as error:
            logger.error(
                "Vault lock failed: %s",
                error
            )


response_engine = ResponseEngine()