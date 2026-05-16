import sqlite3
import os
import time
from hashlib import sha256
from datetime import datetime

DB_PATH = "database/blueteam.db"

def get_connection() -> sqlite3.Connection:
    os.makedirs("database", exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db() -> None:
    conn = get_connection()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            event_type TEXT NOT NULL,
            severity   TEXT NOT NULL,
            details    TEXT NOT NULL,
            timestamp  TEXT NOT NULL,
            hash       TEXT NOT NULL,
            raw        TEXT NOT NULL
        )
    """)
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_events_timestamp_category
        ON events (timestamp, event_type)
    """)
    conn.commit()
    conn.close()
    print("[DB] Initialized.")

def _get_last_entry(conn: sqlite3.Connection) -> dict | None:
    row = conn.execute(
        "SELECT * FROM events ORDER BY id DESC LIMIT 1"
    ).fetchone()
    return dict(row) if row else None

def log_event(event_type: str, severity: str,
              details: str, timestamp: str = None) -> bool:
    try:
        if not timestamp:
            timestamp = datetime.now().isoformat()
        conn = get_connection()
        prev = _get_last_entry(conn)
        prev_hash = prev["hash"] if prev else "0" * 64
        raw = f"{event_type}│{severity}│{details}│{timestamp}"
        h = sha256(f"{prev_hash}{raw}".encode()).hexdigest()
        conn.execute(
            "INSERT INTO events (event_type, severity, details, timestamp, hash, raw) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            [event_type, severity, details, timestamp, h, raw]
        )
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"[DB] log_event error: {e}")
        return False

def get_all_events() -> list:
    conn = get_connection()
    rows = conn.execute(
        "SELECT * FROM events ORDER BY id ASC"
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]

def get_recent_events(limit: int = 50) -> list:
    conn = get_connection()
    rows = conn.execute(
        "SELECT * FROM events ORDER BY id DESC LIMIT ?", [limit]
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]

def verify_chain() -> tuple[bool, str]:
    """
    Verifies the hash chain integrity of all log entries.
    Returns (True, summary) if clean, (False, error) if tampered.
    """
    entries = get_all_events()
    if not entries:
        return True, "No entries to verify."

    prev_hash = "0" * 64
    for i, entry in enumerate(entries):
        expected = sha256(
            f"{prev_hash}{entry['raw']}".encode()
        ).hexdigest()
        if expected != entry["hash"]:
            msg = f"Tamper detected at entry {i} (id={entry['id']})"
            print(f"[DB] {msg}")
            _publish_chain_tampered(entry["id"])
            return False, msg
        prev_hash = entry["hash"]

    return True, f"All {len(entries)} entries verified."

def _publish_chain_tampered(entry_id: int) -> None:
    try:
        from monitor.event_bus import publish
        publish("CHAIN_TAMPERED", "CRITICAL", {
            "message": f"Log chain tampered at entry id={entry_id}",
            "timestamp": time.time()
        })
    except Exception:
        print(f"[DB] CHAIN_TAMPERED at entry id={entry_id}")

def clear_db() -> None:
    """For testing only."""
    conn = get_connection()
    conn.execute("DELETE FROM events")
    conn.commit()
    conn.close()