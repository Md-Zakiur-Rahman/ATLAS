"""Database manager and helpers.

Unified implementation for database operations. Uses the existing
`database.client.supabase` client and provides:
- `DBManager` class (Member B style, with logging)
- helper functions from Member C (whitelist, network, threats, stats, export)
- `DatabaseManager` wrapper class for dashboard compatibility
"""

from __future__ import annotations
from dotenv import load_dotenv
load_dotenv()
import os
import json
import csv
import time
from hashlib import sha256
from datetime import datetime, timedelta
from typing import List, Tuple, Optional

from config.logging_config import get_logger
from database.client import supabase
from monitor.event_bus import event_bus

logger = get_logger("database")


# Whitelist file path
WHITELIST_FILE = os.path.join(os.path.dirname(__file__), "whitelist.json")


class DBManager:
    """Primary database manager used across Member B code.

    Methods use `logger` for output and return sensible types for callers.
    """

    def get_last_entry(self) -> Optional[dict]:
        try:
            result = supabase.table("events").select("*").order("id", desc=True).limit(1).execute()
            rows = result.data or []
            return rows[0] if rows else None
        except Exception as error:
            logger.error("Failed to fetch last event entry: %s", error)
            return None

    def log_event(self, event_type: str, severity: str, details: dict | str = None,
                  category: Optional[str] = None, timestamp: Optional[str] = None) -> Optional[int]:
        """Insert an event with hash chaining. Returns inserted row id or None."""
        try:
            if details is None:
                details = {}

            if not timestamp:
                timestamp = datetime.utcnow().isoformat()

            prev = self.get_last_entry()
            prev_hash = prev.get("hash") if prev else "0" * 64

            raw = f"{event_type}│{severity}│{details}│{timestamp}"
            h = sha256(f"{prev_hash}{raw}".encode()).hexdigest()

            row = supabase.table("events").insert({
                "event_type": event_type,
                "severity": severity,
                "category": category,
                "details": details,
                "timestamp": timestamp,
                "hash": h,
                "raw": raw,
            }).execute()

            event_id = None
            try:
                event_id = row.data[0]["id"]
            except Exception:
                pass

            logger.info("Event logged: %s | %s | id=%s", event_type, severity, event_id)
            return event_id
        except Exception as error:
            logger.exception("Failed to log event: %s", error)
            return None

    def verify_chain(self) -> Tuple[bool, str]:
        try:
            result = supabase.table("events").select("*").order("id", desc=False).execute()
            entries = result.data or []

            if len(entries) < 2:
                message = "Chain too short to verify"
                logger.info(message)
                return True, message

            for i in range(1, len(entries)):
                prev_hash = entries[i - 1]["hash"]
                expected = sha256(f"{prev_hash}{entries[i]['raw']}".encode()).hexdigest()
                if expected != entries[i]["hash"]:
                    message = f"Tamper detected at entry {i} - ID {entries[i].get('id')}"
                    logger.critical(message)
                    return False, message

            message = f"All {len(entries)} entries verified"
            logger.info(message)
            return True, message

        except Exception as error:
            message = f"Chain verification failed: {error}"
            logger.exception(message)
            return False, message

    def verify_on_startup(self) -> None:
        is_clean, message = self.verify_chain()
        if not is_clean:
            event_bus.publish({
                "event_type": "CHAIN_TAMPERED",
                "detail": message,
                "severity": "CRITICAL",
                "timestamp": time.time(),
            })
            logger.critical("Chain verification failed on startup: %s", message)
        else:
            logger.info("Chain verification clean on startup: %s", message)


# --- Member C helpers ---

def load_whitelist() -> dict:
    try:
        if os.path.exists(WHITELIST_FILE):
            with open(WHITELIST_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                return {
                    "processes": data.get("processes", []),
                    "paths": data.get("paths", []),
                    "ips": data.get("ips", []),
                }
    except Exception as e:
        logger.warning("Error loading whitelist: %s", e)
    return {"processes": [], "paths": [], "ips": []}


def is_whitelisted(process: Optional[str] = None, ip: Optional[str] = None, path: Optional[str] = None) -> bool:
    wl = load_whitelist()
    process_match = process in wl.get("processes", []) if process else False
    ip_match = ip in wl.get("ips", []) if ip else False
    path_match = path in wl.get("paths", []) if path else False
    return process_match or ip_match or path_match


def get_events(limit: int = 100, filter_severity: Optional[str] = None,
               filter_category: Optional[str] = None) -> List[dict]:
    try:
        q = supabase.table("events").select("*").order("timestamp", desc=True).limit(limit)
        if filter_severity:
            q = q.eq("severity", filter_severity)
        if filter_category:
            q = q.eq("category", filter_category)
        result = q.execute()
        return result.data or []
    except Exception as e:
        logger.exception("Error fetching events: %s", e)
        return []


def get_network_connections(limit: int = 50) -> List[dict]:
    try:
        result = supabase.table("network_connections").select("*").order("timestamp", desc=True).limit(limit).execute()
        return result.data or []
    except Exception as e:
        logger.exception("Error fetching network connections: %s", e)
        return []


def get_flagged_ips() -> List[dict]:
    try:
        result = supabase.table("network_connections").select("remote_ip, city, country, process, timestamp").eq("threat_flag", True).order("timestamp", desc=True).execute()
        return result.data or []
    except Exception as e:
        logger.exception("Error fetching flagged IPs: %s", e)
        return []


def get_threats(limit: int = 50) -> List[dict]:
    try:
        result = supabase.table("threats").select("*").order("timestamp", desc=True).limit(limit).execute()
        return result.data or []
    except Exception as e:
        logger.exception("Error fetching threats: %s", e)
        return []


def log_network_connection(process: str, local_ip: str, local_port: int,
                           remote_ip: str, remote_port: int,
                           threat_flag: bool = False, city: Optional[str] = None,
                           country: Optional[str] = None) -> Optional[int]:
    try:
        if is_whitelisted(process=process, ip=remote_ip):
            threat_flag = False
            logger.info("Whitelisted connection ignored: %s -> %s", process, remote_ip)
        row = supabase.table("network_connections").insert({
            "process": process,
            "local_ip": local_ip,
            "local_port": local_port,
            "remote_ip": remote_ip,
            "remote_port": remote_port,
            "threat_flag": threat_flag,
            "city": city,
            "country": country,
            "timestamp": datetime.now().isoformat(),
        }).execute()
        return row.data[0].get("id") if row.data else None
    except Exception as e:
        logger.exception("Error logging network connection: %s", e)
        return None


def log_file_rename(original: str, renamed_to: str) -> Optional[int]:
    try:
        row = supabase.table("rename_log").insert({
            "original": original,
            "renamed_to": renamed_to,
            "rolled_back": False,
            "timestamp": datetime.now().isoformat(),
        }).execute()
        return row.data[0].get("id") if row.data else None
    except Exception as e:
        logger.exception("Error logging file rename: %s", e)
        return None


def mark_rename_rolled_back(rename_id: int) -> None:
    try:
        supabase.table("rename_log").update({"rolled_back": True}).eq("id", rename_id).execute()
    except Exception as e:
        logger.exception("Error marking rename as rolled back: %s", e)


def log_threat(event_id: int, category: str, source_ip: Optional[str] = None,
               process: Optional[str] = None, severity: Optional[str] = None) -> Optional[int]:
    try:
        row = supabase.table("threats").insert({
            "event_id": event_id,
            "category": category,
            "source_ip": source_ip,
            "process": process,
            "severity": severity,
            "timestamp": datetime.now().isoformat(),
        }).execute()
        return row.data[0].get("id") if row.data else None
    except Exception as e:
        logger.exception("Error logging threat: %s", e)
        return None


def create_user(name: str, email: str, password_hash: str, phone_last5: str,
                device_fingerprint: str) -> Optional[int]:
    try:
        row = supabase.table("auth").insert({
            "name": name,
            "email": email,
            "password_hash": password_hash,
            "phone_last5": phone_last5,
            "device_fingerprint": device_fingerprint,
            "telegram_linked": False,
            "created_at": datetime.now().isoformat(),
        }).execute()
        return row.data[0].get("id") if row.data else None
    except Exception as e:
        logger.exception("Error creating user: %s", e)
        return None


def get_user_by_email(email: str) -> Optional[dict]:
    try:
        result = supabase.table("auth").select("*").eq("email", email).execute()
        return result.data[0] if result.data else None
    except Exception as e:
        logger.exception("Error fetching user: %s", e)
        return None


def link_telegram(email: str) -> None:
    try:
        supabase.table("auth").update({"telegram_linked": True}).eq("email", email).execute()
    except Exception as e:
        logger.exception("Error linking Telegram: %s", e)


def verify_chain() -> Tuple[bool, str]:
    try:
        entries = supabase.table("events").select("*").order("id").execute().data
        if not entries:
            return True, "Chain empty — nothing to verify"
        for i, entry in enumerate(entries):
            prev_hash = "0" * 64 if i == 0 else entries[i - 1]["hash"]
            expected = sha256(f"{prev_hash}{entry['raw']}".encode()).hexdigest()
            if expected != entry["hash"]:
                return False, f"Tamper detected at entry {i + 1} (id={entry['id']})"
        return True, f"All {len(entries)} entries verified — chain intact"
    except Exception as e:
        logger.exception("Error verifying chain: %s", e)
        return False, f"Chain verification error: {e}"


def export_events_csv(filepath: str, limit: int = 1000) -> None:
    try:
        events = get_events(limit=limit)
        if not events:
            logger.info("No events to export")
            return
        keys = events[0].keys()
        with open(filepath, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=keys)
            writer.writeheader()
            writer.writerows(events)
        logger.info("Exported %d events to %s", len(events), filepath)
    except Exception as e:
        logger.exception("Error exporting CSV: %s", e)


def clear_old_events(days: int = 30) -> None:
    try:
        cutoff = (datetime.now() - timedelta(days=days)).isoformat()
        supabase.table("events").delete().lt("timestamp", cutoff).execute()
        logger.info("Cleared events older than %d days", days)
    except Exception as e:
        logger.exception("Error clearing old events: %s", e)


def get_event_stats(hours: int = 24) -> dict:
    try:
        cutoff_time = (datetime.now() - timedelta(hours=hours)).isoformat()
        result = supabase.table("events").select("*").gte("timestamp", cutoff_time).execute()
        events = result.data or []
        return {
            "total_events": len(events),
            "critical_threats": len([e for e in events if e.get("severity") == "CRITICAL"]),
            "high_threats": len([e for e in events if e.get("severity") == "HIGH"]),
            "medium_threats": len([e for e in events if e.get("severity") == "MEDIUM"]),
            "low_events": len([e for e in events if e.get("severity") == "LOW"]),
        }
    except Exception as e:
        logger.exception("Error getting event stats: %s", e)
        return {"total_events": 0, "critical_threats": 0, "high_threats": 0, "medium_threats": 0, "low_events": 0}


def get_encryption_stats(hours: int = 24) -> dict:
    try:
        cutoff_time = (datetime.now() - timedelta(hours=hours)).isoformat()
        result = supabase.table("events").select("*").gte("timestamp", cutoff_time).ilike("event_type", "%ENCRYPT%").execute()
        events = result.data or []
        total_size = 0
        for event in events:
            if event.get("details") and isinstance(event.get("details"), dict):
                total_size += event["details"].get("file_size", 0)
        return {"files_encrypted": len(events), "total_size_mb": round(total_size / (1024 * 1024), 2)}
    except Exception as e:
        logger.exception("Error getting encryption stats: %s", e)
        return {"files_encrypted": 0, "total_size_mb": 0}


def get_events_by_hour(hours: int = 24) -> list:
    try:
        cutoff_time = (datetime.now() - timedelta(hours=hours)).isoformat()
        result = supabase.table("events").select("timestamp, severity").gte("timestamp", cutoff_time).order("timestamp", desc=True).execute()
        events = result.data or []
        hourly_data = {}
        for event in events:
            if event.get("timestamp"):
                hour = event["timestamp"][:13]
                if hour not in hourly_data:
                    hourly_data[hour] = {"total": 0, "critical": 0}
                hourly_data[hour]["total"] += 1
                if event.get("severity") == "CRITICAL":
                    hourly_data[hour]["critical"] += 1
        return list(hourly_data.items())
    except Exception as e:
        logger.exception("Error getting events by hour: %s", e)
        return []


def get_threats_filtered(limit: int = 50, hours: Optional[int] = None) -> List[dict]:
    try:
        q = supabase.table("threats").select("*").order("timestamp", desc=True).limit(limit)
        if hours:
            cutoff_time = (datetime.now() - timedelta(hours=hours)).isoformat()
            q = q.gte("timestamp", cutoff_time)
        result = q.execute()
        return result.data or []
    except Exception as e:
        logger.exception("Error fetching threats: %s", e)
        return []


class DatabaseManager:
    """Wrapper class to provide a stable interface for dashboard code (Member C)."""

    def __init__(self):
        self._db = DBManager()

    def get_events(self, limit: int = 100, severity: Optional[str] = None, category: Optional[str] = None):
        try:
            q = supabase.table("events").select("*").order("timestamp", desc=True).limit(limit)
            if severity and severity != "All":
                q = q.eq("severity", severity)
            if category:
                q = q.eq("category", category)
            result = q.execute()
            return result.data or []
        except Exception as e:
            logger.exception("Error fetching events: %s", e)
            return []

    def get_event_stats(self, hours: int = 24) -> dict:
        return get_event_stats(hours)

    def get_encryption_stats(self, hours: int = 24) -> dict:
        return get_encryption_stats(hours)

    def get_events_by_hour(self, hours: int = 24) -> list:
        return get_events_by_hour(hours)

    def get_threats(self, limit: int = 50, hours: int = None) -> list:
        return get_threats_filtered(limit, hours)

    def get_network_connections(self, limit: int = 50):
        return get_network_connections(limit)

    def get_flagged_ips(self):
        return get_flagged_ips()

    def export_events_csv(self, filepath: str, limit: int = 1000):
        return export_events_csv(filepath, limit)

    def clear_old_events(self, days: int = 30):
        return clear_old_events(days)

    def log_event(self, event_type: str, severity: str, details: dict = None,
                  category: str = None, timestamp: str = None) -> Optional[int]:
        return self._db.log_event(event_type, severity, details, category, timestamp)

    def log_network_connection(self, process: str, local_ip: str, local_port: int,
                               remote_ip: str, remote_port: int,
                               threat_flag: bool = False, city: str = None,
                               country: str = None) -> Optional[int]:
        return log_network_connection(process, local_ip, local_port, remote_ip, remote_port, threat_flag, city, country)

    def log_threat(self, event_id: int, category: str, source_ip: str = None,
                   process: str = None, severity: str = None) -> Optional[int]:
        return log_threat(event_id, category, source_ip, process, severity)


db_manager = DBManager()
db = DatabaseManager()


if __name__ == "__main__":
    logger.info("Testing Supabase connection and DB helpers...")
    eid = db_manager.log_event("TEST", "LOW", {"test": "connection_successful"}, category="SETUP")
    logger.info("Test event inserted id=%s", eid)
    events = db.get_events(limit=5)
    logger.info("Retrieved %d recent events", len(events))
    is_valid, msg = db_manager.verify_chain()
    logger.info("Chain verification: %s", msg)


def log_event(event_type: str, severity: str, details: dict | str = None,
              category: Optional[str] = None, timestamp: Optional[str] = None) -> Optional[int]:
    """Module-level wrapper to maintain backwards compatibility with
    previous API (and `database.__init__` exports). Delegates to
    `db_manager.log_event`.
    """
    return db_manager.log_event(event_type, severity, details, category, timestamp)
