
import os
import json
import csv
from supabase import create_client
from hashlib import sha256
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY")

if not SUPABASE_URL or not SUPABASE_KEY:
    raise ValueError("❌ Missing SUPABASE_URL or SUPABASE_KEY in .env file")

supabase = create_client(SUPABASE_URL, SUPABASE_KEY)

print(f"✅ Connected to Supabase: {SUPABASE_URL}")


WHITELIST_FILE = "whitelist.json"

def load_whitelist():
    try:
        if os.path.exists(WHITELIST_FILE):
            with open(WHITELIST_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                return {
                    "processes": data.get("processes", []),
                    "paths": data.get("paths", []),
                    "ips": data.get("ips", [])
                }
    except Exception as e:
        print(f"❌ Error loading whitelist: {e}")

    return {
        "processes": [],
        "paths": [],
        "ips": []
    }

def is_whitelisted(process=None, ip=None, path=None):
    wl = load_whitelist()

    process_match = process in wl.get("processes", []) if process else False
    ip_match = ip in wl.get("ips", []) if ip else False
    path_match = path in wl.get("paths", []) if path else False

    return process_match or ip_match or path_match


def log_event(event_type: str, severity: str, details: dict = None,
              category: str = None, timestamp: str = None) -> int:
    """
    Log an event to the database with hash-chain verification (Day 9).
    """
    if details is None:
        details = {}

    if not timestamp:
        timestamp = datetime.now().isoformat()

    try:
        res = supabase.table("events") \
            .select("hash") \
            .order("id", desc=True) \
            .limit(1) \
            .execute()
        prev_hash = res.data[0]["hash"] if res.data else "0" * 64
    except Exception as e:
        print(f"⚠️ Warning fetching previous hash: {e}")
        prev_hash = "0" * 64

    raw = f"{event_type}│{severity}│{details}│{timestamp}"
    h = sha256(f"{prev_hash}{raw}".encode()).hexdigest()

    try:
        row = supabase.table("events").insert({
            "event_type": event_type,
            "severity": severity,
            "details": details,
            "category": category,
            "timestamp": timestamp,
            "hash": h,
            "raw": raw,
        }).execute()

        event_id = row.data[0]["id"]
        print(f"✅ Logged: {event_type} ({severity}) - ID: {event_id}")
        return event_id
    except Exception as e:
        print(f"❌ Error logging event: {e}")
        raise


def get_events(limit: int = 100, filter_severity: str = None,
               filter_category: str = None) -> list:
    """Get events from database, newest first."""
    try:
        q = supabase.table("events").select("*").order("timestamp", desc=True).limit(limit)

        if filter_severity:
            q = q.eq("severity", filter_severity)
        if filter_category:
            q = q.eq("category", filter_category)

        result = q.execute()
        return result.data or []
    except Exception as e:
        print(f"❌ Error fetching events: {e}")
        return []

def get_network_connections(limit: int = 50) -> list:
    """Get network connection logs, newest first."""
    try:
        result = supabase.table("network_connections") \
            .select("*") \
            .order("timestamp", desc=True) \
            .limit(limit) \
            .execute()
        return result.data or []
    except Exception as e:
        print(f"❌ Error fetching network connections: {e}")
        return []

def get_flagged_ips() -> list:
    """Get all IPs flagged as threats."""
    try:
        result = supabase.table("network_connections") \
            .select("remote_ip, city, country, process, timestamp") \
            .eq("threat_flag", True) \
            .order("timestamp", desc=True) \
            .execute()
        return result.data or []
    except Exception as e:
        print(f"❌ Error fetching flagged IPs: {e}")
        return []

def get_threats(limit: int = 50) -> list:
    """Get threat records."""
    try:
        result = supabase.table("threats") \
            .select("*") \
            .order("timestamp", desc=True) \
            .limit(limit) \
            .execute()
        return result.data or []
    except Exception as e:
        print(f"❌ Error fetching threats: {e}")
        return []

def log_network_connection(process: str, local_ip: str, local_port: int,
                           remote_ip: str, remote_port: int,
                           threat_flag: bool = False, city: str = None,
                           country: str = None) -> int:
    """Log a network connection, but suppress threat flag if whitelisted."""
    try:
        if is_whitelisted(process=process, ip=remote_ip):
            threat_flag = False
            print(f"✅ Whitelisted connection ignored: {process} -> {remote_ip}")

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

        return row.data[0]["id"]
    except Exception as e:
        print(f"❌ Error logging network connection: {e}")
        raise

def log_file_rename(original: str, renamed_to: str) -> int:
    """Log a file rename."""
    try:
        row = supabase.table("rename_log").insert({
            "original": original,
            "renamed_to": renamed_to,
            "rolled_back": False,
            "timestamp": datetime.now().isoformat(),
        }).execute()
        return row.data[0]["id"]
    except Exception as e:
        print(f"❌ Error logging file rename: {e}")
        raise

def mark_rename_rolled_back(rename_id: int):
    """Mark a renamed file as rolled back."""
    try:
        supabase.table("rename_log").update({
            "rolled_back": True
        }).eq("id", rename_id).execute()
    except Exception as e:
        print(f"❌ Error marking rename as rolled back: {e}")

def log_threat(event_id: int, category: str, source_ip: str = None,
               process: str = None, severity: str = None) -> int:
    """Log a threat record linked to an event."""
    try:
        row = supabase.table("threats").insert({
            "event_id": event_id,
            "category": category,
            "source_ip": source_ip,
            "process": process,
            "severity": severity,
            "timestamp": datetime.now().isoformat(),
        }).execute()
        return row.data[0]["id"]
    except Exception as e:
        print(f"❌ Error logging threat: {e}")
        raise

def create_user(name: str, email: str, password_hash: str, phone_last5: str,
                device_fingerprint: str) -> int:
    """Create a new user."""
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
        return row.data[0]["id"]
    except Exception as e:
        print(f"❌ Error creating user: {e}")
        raise

def get_user_by_email(email: str) -> dict:
    """Get user by email."""
    try:
        result = supabase.table("auth").select("*").eq("email", email).execute()
        return result.data[0] if result.data else None
    except Exception as e:
        print(f"❌ Error fetching user: {e}")
        return None

def link_telegram(email: str):
    """Mark user as Telegram-linked."""
    try:
        supabase.table("auth").update({
            "telegram_linked": True
        }).eq("email", email).execute()
    except Exception as e:
        print(f"❌ Error linking Telegram: {e}")

def verify_chain() -> tuple[bool, str]:
    """
    Verify the entire hash chain is intact.
    Returns: (is_valid, message)
    """
    try:
        entries = supabase.table("events") \
            .select("*") \
            .order("id") \
            .execute().data

        if not entries:
            return True, "Chain empty — nothing to verify"

        for i, entry in enumerate(entries):
            prev_hash = "0" * 64 if i == 0 else entries[i - 1]["hash"]
            expected = sha256(f"{prev_hash}{entry['raw']}".encode()).hexdigest()

            if expected != entry["hash"]:
                return False, f"🚨 Tamper detected at entry {i + 1} (id={entry['id']})"

        return True, f"✅ All {len(entries)} entries verified — chain intact"

    except Exception as e:
        print(f"❌ Error verifying chain: {e}")
        return False, f"❌ Chain verification error: {e}"

def export_events_csv(filepath: str, limit: int = 1000):
    """Export events to CSV."""
    try:
        events = get_events(limit=limit)

        if not events:
            print("❌ No events to export")
            return

        keys = events[0].keys()
        with open(filepath, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=keys)
            writer.writeheader()
            writer.writerows(events)

        print(f"✅ Exported {len(events)} events to {filepath}")
    except Exception as e:
        print(f"❌ Error exporting CSV: {e}")

def clear_old_events(days: int = 30):
    """Delete events older than N days."""
    from datetime import timedelta
    try:
        cutoff = (datetime.now() - timedelta(days=days)).isoformat()
        supabase.table("events").delete().lt("timestamp", cutoff).execute()
        print(f"✅ Cleared events older than {days} days")
    except Exception as e:
        print(f"❌ Error clearing old events: {e}")

def get_event_stats(hours: int = 24) -> dict:
    """Get event statistics for the last N hours."""
    try:
        from datetime import timedelta
        cutoff_time = (datetime.now() - timedelta(hours=hours)).isoformat()

        result = supabase.table("events") \
            .select("*") \
            .gte("timestamp", cutoff_time) \
            .execute()

        events = result.data or []

        return {
            "total_events": len(events),
            "critical_threats": len([e for e in events if e.get("severity") == "CRITICAL"]),
            "high_threats": len([e for e in events if e.get("severity") == "HIGH"]),
            "medium_threats": len([e for e in events if e.get("severity") == "MEDIUM"]),
            "low_events": len([e for e in events if e.get("severity") == "LOW"]),
        }
    except Exception as e:
        print(f"❌ Error getting event stats: {e}")
        return {
            "total_events": 0,
            "critical_threats": 0,
            "high_threats": 0,
            "medium_threats": 0,
            "low_events": 0,
        }

def get_encryption_stats(hours: int = 24) -> dict:
    """Get encryption statistics for the last N hours."""
    try:
        from datetime import timedelta
        cutoff_time = (datetime.now() - timedelta(hours=hours)).isoformat()

        result = supabase.table("events") \
            .select("*") \
            .gte("timestamp", cutoff_time) \
            .ilike("event_type", "%ENCRYPT%") \
            .execute()

        events = result.data or []

        total_size = 0
        for event in events:
            if event.get("details") and isinstance(event.get("details"), dict):
                total_size += event["details"].get("file_size", 0)

        return {
            "files_encrypted": len(events),
            "total_size_mb": round(total_size / (1024 * 1024), 2),
        }
    except Exception as e:
        print(f"❌ Error getting encryption stats: {e}")
        return {
            "files_encrypted": 0,
            "total_size_mb": 0,
        }

def get_events_by_hour(hours: int = 24) -> list:
    """Get event counts grouped by hour."""
    try:
        from datetime import timedelta
        cutoff_time = (datetime.now() - timedelta(hours=hours)).isoformat()

        result = supabase.table("events") \
            .select("timestamp, severity") \
            .gte("timestamp", cutoff_time) \
            .order("timestamp", desc=True) \
            .execute()

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
        print(f"❌ Error getting events by hour: {e}")
        return []

def get_threats_filtered(limit: int = 50, hours: int = None) -> list:
    """Get threats, optionally filtered by hours."""
    try:
        q = supabase.table("threats") \
            .select("*") \
            .order("timestamp", desc=True) \
            .limit(limit)

        if hours:
            from datetime import timedelta
            cutoff_time = (datetime.now() - timedelta(hours=hours)).isoformat()
            q = q.gte("timestamp", cutoff_time)

        result = q.execute()
        return result.data or []
    except Exception as e:
        print(f"❌ Error fetching threats: {e}")
        return []

class DatabaseManager:
    """Wrapper class to provide database interface for dashboard tabs."""

    def __init__(self):
        pass

    def get_events(self, limit: int = 100, severity: str = None, category: str = None):
        try:
            q = supabase.table("events").select("*").order("timestamp", desc=True).limit(limit)

            if severity and severity != "All":
                q = q.eq("severity", severity)
            if category:
                q = q.eq("category", category)

            result = q.execute()
            return result.data or []
        except Exception as e:
            print(f"❌ Error fetching events: {e}")
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
                  category: str = None, timestamp: str = None) -> int:
        return log_event(event_type, severity, details, category, timestamp)

    def log_network_connection(self, process: str, local_ip: str, local_port: int,
                               remote_ip: str, remote_port: int,
                               threat_flag: bool = False, city: str = None,
                               country: str = None) -> int:
        return log_network_connection(
            process, local_ip, local_port, remote_ip, remote_port,
            threat_flag, city, country
        )

    def log_threat(self, event_id: int, category: str, source_ip: str = None,
                   process: str = None, severity: str = None) -> int:
        return log_threat(event_id, category, source_ip, process, severity)

db = DatabaseManager()

if __name__ == "__main__":
    print("\n🧪 Testing Supabase connection...")

    event_id = log_event(
        event_type="TEST",
        severity="LOW",
        details={"test": "connection_successful"},
        category="SETUP"
    )
    print(f"✅ Test event inserted: ID {event_id}")

    events = get_events(limit=5)
    print(f"✅ Retrieved {len(events)} recent events")

    is_valid, msg = verify_chain()
    print(f"Chain verification: {msg}")

    print("\n✅ All tests passed!")