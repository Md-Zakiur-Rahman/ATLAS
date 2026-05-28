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
from dotenv import load_dotenv
load_dotenv()

import logging
import time
import os
import socket
import uuid
import json
import threading
from collections import defaultdict, deque
from datetime import datetime
from pathlib import Path

import psutil

from config.logging_config import get_logger
from database.client import supabase
from database.db_manager import log_event
from core.crypto_service import activate_vault_lock
from core.runtime_state import runtime_state
from core.vault import (
    VAULT_FORENSIC_LOGS,
    backup_folder_snapshot,
    ensure_vault_structure,
    isolate_folder,
    release_folder,
)
from auth.vault_auth import vault_auth_manager
from monitor.event_bus import event_bus
from monitor.rules import DEFAULT_MONITOR_PATH
from notifications.email_sender import email_sender

logger = get_logger("responses")

# --- Persistent Containment Log ---
containment_logger = get_logger("containment")


class ResponseEngine:

    def __init__(self):
        ensure_vault_structure()
        self.containment_cooldown_seconds = 300
        self._recent_file_events = deque(maxlen=500)
        self._active_folder_containment: dict[str, float] = {}
        self._trusted_processes = {"chrome.exe", "msedge.exe", "code.exe", "explorer.exe", "winword.exe", "onedrive.exe"}
        self._benign_path_markers = ("\\cache\\", "\\temp\\", "\\tmp\\", "\\steam\\", "\\epic games\\", "\\nvidia\\")
        event_bus.subscribe(
            self.process_event
        )

    def process_event(
        self,
        event
    ) -> None:
        active_email = runtime_state.snapshot().get("current_email")
        if runtime_state.snapshot().get("replay_active"):
            return

        if active_email and "email" not in event:
            event["email"] = active_email

        event_type = event.get("event_type", "")
        severity   = event.get("severity", "")

        # --- Authoritative Rule-Based Containment ---
        if event_type == "HONEYPOT_DIRECTORY_ACCESS":
            self.handle_honeypot_access(event)
            return

        if event_type == "VAULT_LOCKED":
            logger.info("VAULT_LOCKED event observed; no further escalation needed.")
            return

        # AUTH_BRUTE_FORCE - handle and
        # return early, unchanged from
        # original.
        if event_type == "AUTH_BRUTE_FORCE":
            self.handle_auth_bruteforce(event)
            return

        # Handle ransomware-like activity
        if event_type == "POSSIBLE_RANSOMWARE_ACTIVITY":
            self.handle_ransomware_activity(event)
            return

        if event_type == "EXFILTRATION_PATTERN_DETECTED":
            self.handle_exfiltration(event)
            return

        if event_type == "TOKEN_ABUSE_BURST":
            self.handle_token_abuse(event)
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
                if event.get("confirmed") or event.get("chained"):
                    self.handle_ml_critical(event)
                else:
                    self.handle_ml_high(event)

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
            # Network events are informational unless explicit risk reasons exist.
            if event.get("suspicious") and event.get("risk_reasons"):
                self.handle_medium_threat(event)
            return

        if event_type == "TARGETED_CONTAINMENT":
            logger.critical(
                "Targeted containment active | folder=%s | process=%s",
                event.get("attacked_folder"),
                event.get("attacking_process"),
            )
            runtime_state.add_alert(
                {
                    "type": "TARGETED_CONTAINMENT",
                    "severity": "CRITICAL",
                    "timestamp": event.get("timestamp", time.time()),
                    "details": event,
                }
            )
            return

        if event_type in {"FILE_MODIFIED", "FILE_RENAMED", "FILE_CREATED", "FILE_DELETED"}:
            self._handle_file_telemetry(event)
            return

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

    def _handle_file_telemetry(self, event: dict) -> None:
        folder = str(event.get("folder") or Path(str(event.get("path", ""))).parent)
        process = str(event.get("process_name") or "UNKNOWN")
        normalized_process = process.lower()
        now = time.time()

        if any(marker in folder.lower() for marker in self._benign_path_markers):
            return
        if normalized_process in self._trusted_processes:
            return

        self._recent_file_events.append(
            {
                "ts": now,
                "event_type": event.get("event_type"),
                "path": event.get("path"),
                "folder": folder,
                "process": process,
                "pid": event.get("pid"),
                "entropy": float(event.get("entropy") or 0.0),
            }
        )
        window = [row for row in self._recent_file_events if now - row["ts"] <= 20 and row["folder"] == folder]
        if len(window) < 8:
            return

        same_process_counts = defaultdict(int)
        per_file_writes = defaultdict(int)
        entropy_spikes = 0
        modifications = 0
        for row in window:
            same_process_counts[row["process"]] += 1
            if row["type"] in {"FILE_MODIFIED", "FILE_RENAMED"}:
                modifications += 1
            per_file_writes[row["path"]] += 1
            if row["entropy"] >= 7.3:
                entropy_spikes += 1

        repeated_writes = sum(1 for count in per_file_writes.values() if count >= 3)
        max_process, max_count = max(same_process_counts.items(), key=lambda kv: kv[1])
        same_process_mass_mod = max_count >= 6
        rapid_modifications = modifications >= 8
        short_window_correlation = len(window) >= 10

        signals = {
            "rapid_file_modifications": rapid_modifications,
            "repeated_writes": repeated_writes >= 2,
            "entropy_spikes": entropy_spikes >= 3,
            "same_process_mass_modifications": same_process_mass_mod,
            "short_time_window_correlation": short_window_correlation,
        }
        positive = sum(1 for v in signals.values() if v)
        if positive < 3:
            return

        attacker_pid = None
        for row in reversed(window):
            if row["process"] == max_process and row.get("pid"):
                attacker_pid = row["pid"]
                break
        self._contain_folder_attack(folder, max_process, attacker_pid, signals, len(window))

    def _contain_folder_attack(self, folder: str, process_name: str, pid: int | None, signals: dict, event_count: int) -> None:
        now = time.time()
        until = self._active_folder_containment.get(folder, 0)
        if until > now:
            return
        self._active_folder_containment[folder] = now + self.containment_cooldown_seconds

        killed = False
        if pid:
            try:
                psutil.Process(int(pid)).kill()
                killed = True
            except Exception as error:
                logger.warning("Containment process termination failed for pid=%s: %s", pid, error)

        snapshot_path = backup_folder_snapshot(folder)
        isolation = isolate_folder(folder)
        forensic = {
            "timestamp": datetime.utcnow().isoformat(),
            "attacked_folder": folder,
            "attacking_process": process_name,
            "attacker_pid": pid,
            "process_terminated": killed,
            "signals": signals,
            "window_events": event_count,
            "backup_snapshot": snapshot_path,
            "isolation_marker": isolation.get("marker"),
            "cooldown_seconds": self.containment_cooldown_seconds,
        }
        log_file = VAULT_FORENSIC_LOGS / f"containment_{int(now)}.json"
        log_file.write_text(json.dumps(forensic, indent=2), encoding="utf-8")
        log_event(
            event_type="TARGETED_CONTAINMENT",
            severity="CRITICAL",
            details=forensic,
            category="CONTAINMENT",
        )

        runtime_state.set_nested(
            "containment_state",
            {
                "active": True,
                "state": "CONTAINED",
                "attacked_folder": folder,
                "attacking_process": process_name,
                "attacker_pid": pid,
                "forensic_log": str(log_file),
                "backup_snapshot": snapshot_path,
                "recovery_options": "Restore from vault/backups or release containment after cooldown.",
                "cooldown_ends_at": now + self.containment_cooldown_seconds,
            },
        )
        event_bus.publish(
            {
                "event_type": "TARGETED_CONTAINMENT",
                "severity": "CRITICAL",
                "ransomware_detected": True,
                "confirmed_critical": True,
                "attacked_folder": folder,
                "attacking_process": process_name,
                "attacker_pid": pid,
                "forensic_log": str(log_file),
                "cooldown_ends_at": now + self.containment_cooldown_seconds,
                "timestamp": now,
            }
        )
        email_sender.send_critical_alert(
            {
                "event_type": "TARGETED_CONTAINMENT",
                "ransomware_detected": True,
                "pid": pid,
                "process_name": process_name,
                "attacked_folder": folder,
            },
            self._capture_screenshot(),
        )
        containment_logger.info(
            "EVENT=TARGETED_CONTAINMENT | "
            f"FOLDER={folder} | "
            f"PROCESS={process_name} | "
            f"PID={pid} | "
            f"SIGNALS={signals}"
        )
        threading.Thread(target=self._recover_folder_after_cooldown, args=(folder,), daemon=True).start()

    def _recover_folder_after_cooldown(self, folder: str) -> None:
        until = self._active_folder_containment.get(folder, time.time())
        sleep_for = max(0, until - time.time())
        time.sleep(sleep_for)
        release = release_folder(folder)
        runtime_state.set_nested(
            "containment_state",
            {
                "active": False,
                "state": "RECOVERED",
                "attacked_folder": folder,
                "restored_items": release.get("restored_items", 0),
                "recovery_options": "Folder writes restored. You can review forensic logs and backups.",
            },
        )
        event_bus.publish(
            {
                "event_type": "CONTAINMENT_RECOVERED",
                "severity": "LOW",
                "attacked_folder": folder,
                "timestamp": time.time(),
            }
        )

    def handle_honeypot_access(self, event: dict):
        """Immediate, critical response to any honeypot access."""
        path = event.get("path", "N/A")
        action = event.get("action", "access")
        reason = f"Honeypot directory access detected ({action}): {path}"
        logger.critical(reason)

        # 1. Lock the vault immediately
        activate_vault_lock(reason)

        # 2. Log the critical event with details
        details = {"reason": reason, "path": path, "action": action}
        log_event(
            event_type="VAULT_LOCKED_AUTOMATIC",
            severity="CRITICAL",
            details=details,
            category="CONTAINMENT",
        )

        # 3. Publish VAULT_LOCKED event for UI and other subscribers
        event_bus.publish({
            "event_type": "VAULT_LOCKED",
            "reason": "HONEYPOT_DIRECTORY_ACCESS",
            "severity": "CRITICAL",
            "timestamp": time.time(),
        })

        # 4. Send email notification
        email_sender.send_critical_alert(event, self._capture_screenshot())

        # 5. Persist lock state to user's vault profile
        if event.get("email"):
            vault_auth_manager.lock_vault(event["email"], reason="HONEYPOT_DIRECTORY_ACCESS", severity="CRITICAL")

    def handle_ransomware_activity(self, event: dict):
        """Response to mass file modification events."""
        reason = "Possible ransomware activity detected (mass file modification)"
        logger.critical(reason)
        activate_vault_lock(reason)
        details = {"reason": reason, "details": event.get("details")}
        log_event(event_type="VAULT_LOCKED_AUTOMATIC", severity="CRITICAL", details=details, category="CONTAINMENT")
        event_bus.publish({"event_type": "VAULT_LOCKED", "reason": "POSSIBLE_RANSOMWARE_ACTIVITY", "severity": "CRITICAL", "timestamp": time.time()})
        email_sender.send_critical_alert(event, self._capture_screenshot())
        if event.get("email"):
            vault_auth_manager.lock_vault(event["email"], reason="POSSIBLE_RANSOMWARE_ACTIVITY", severity="CRITICAL")

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
            "event_type":      "ML_HIGH_ALERT",
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

        logger.critical("ML CRITICAL anomaly confirmed/chained - containment path")

        if event.get("confirmed") or event.get("chained") or int(event.get("repeat_count", 0)) >= 3:
            event_bus.publish({
                "event_type": "VAULT_LOCKED",
                "reason": "ML anomaly score CRITICAL",
                "severity": "CRITICAL",
                "timestamp": time.time(),
            })
            activate_vault_lock("ML anomaly score CRITICAL")
            containment_logger.info(
                "EVENT=VAULT_LOCK | "
                "REASON=ML_CRITICAL_ANOMALY | "
                f"SCORE={event.get('score')}"
            )

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

        should_lock_vault = bool(
            event.get("confirmed_critical")
            or event.get("ransomware_detected")
            or int(event.get("repeat_count", 0)) >= 3
        )

        if should_lock_vault:
            event_bus.publish({
                "event_type": "VAULT_LOCKED",
                "reason": event.get("event_type", "CRITICAL_THREAT"),
                "severity": "CRITICAL",
                "timestamp": time.time(),
            })
            activate_vault_lock(event.get("event_type", "CRITICAL_THREAT"))
            containment_logger.info(
                "EVENT=VAULT_LOCK | "
                f"REASON={event.get('event_type', 'CRITICAL_THREAT')} | "
                f"PID={pid}"
            )
            if event.get("email"):
                vault_auth_manager.lock_vault(event["email"], reason=event.get("type", "CRITICAL_THREAT"), severity="CRITICAL")

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
                "event_type":      "VAULT_LOCKED",
                "email":     email,
                "severity":  "CRITICAL",
                "timestamp": time.time(),
            })
            activate_vault_lock("AUTH_BRUTE_FORCE")
            containment_logger.info(
                "EVENT=VAULT_LOCK | "
                "REASON=AUTH_BRUTE_FORCE | "
                f"EMAIL={email}"
            )
            vault_auth_manager.lock_vault(email, reason="AUTH_BRUTE_FORCE", severity="CRITICAL")

            email_sender.send_critical_alert(event)

        except Exception as error:
            logger.error(
                "Vault lock failed: %s",
                error
            )


response_engine = ResponseEngine()
