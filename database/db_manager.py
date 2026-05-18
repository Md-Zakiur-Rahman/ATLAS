from hashlib import sha256
from datetime import datetime
import logging
import time
from database.client import supabase
from monitor.event_bus import event_bus


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
)
logger = logging.getLogger("ATLAS-DBManager")


class DBManager:

    def get_last_entry(self) -> dict:
        try:
            result = (
                supabase
                .table("events")
                .select("*")
                .order("id", desc=True)
                .limit(1)
                .execute()
            )
            rows = result.data or []
            return rows[0] if rows else None
        except Exception as error:
            logger.error("Failed to fetch last event entry: %s", error)
            return None

    def log_event(
        self,
        event_type: str,
        severity: str,
        details: str,
        timestamp: str = None,
    ) -> bool:
        try:
            if not timestamp:
                timestamp = datetime.utcnow().isoformat()

            prev = self.get_last_entry()
            prev_hash = prev["hash"] if prev else "0" * 64
            raw = f"{event_type}|{severity}|{details}|{timestamp}"
            h = sha256(f"{prev_hash}{raw}".encode()).hexdigest()

            supabase.table("events").insert({
                "event_type": event_type,
                "severity": severity,
                "category": None,
                "details": details,
                "timestamp": timestamp,
                "hash": h,
                "raw": raw,
            }).execute()

            logger.info("Event logged successfully: %s | %s", event_type, severity)
            return True
        except Exception as error:
            logger.error("Failed to log event: %s", error)
            return False

    def verify_chain(self) -> tuple[bool, str]:
        try:
            result = (
                supabase
                .table("events")
                .select("*")
                .order("id", desc=False)
                .execute()
            )
            entries = result.data or []

            if len(entries) < 2:
                message = "Chain too short to verify"
                logger.info(message)
                return True, message

            for i, entry in enumerate(entries[1:], 1):
                expected = sha256(
                    f"{entries[i-1]['hash']}{entry['raw']}".encode()
                ).hexdigest()
                if expected != entry["hash"]:
                    message = f"Tamper detected at entry {i} - ID {entry.get('id')}"
                    logger.critical(message)
                    return False, message

            message = f"All {len(entries)} entries verified"
            logger.info(message)
            return True, message

        except Exception as error:
            message = f"Chain verification failed: {error}"
            logger.error(message)
            return False, message

    def verify_on_startup(self) -> None:
        is_clean, message = self.verify_chain()

        if not is_clean:
            event_bus.publish({
                "type": "CHAIN_TAMPERED",
                "detail": message,
                "severity": "CRITICAL",
                "timestamp": time.time(),
            })
            logger.critical("Chain verification failed on startup: %s", message)
        else:
            logger.info("Chain verification clean on startup: %s", message)


db_manager = DBManager()
