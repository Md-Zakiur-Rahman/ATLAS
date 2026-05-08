import sqlite3
from datetime import datetime
from typing import List, Dict, Optional
from enum import Enum
import json
import os

class ThreatLevel(Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class DatabaseManager:
    def __init__(self, db_path: str = "logs/events.db"):
        self.db_path = db_path
        self.schema_path = "database/schema.sql"
        
        # Create logs directory if it doesn't exist
        os.makedirs(os.path.dirname(db_path) if os.path.dirname(db_path) else "logs", exist_ok=True)
        
        self.init_db()
    
    def init_db(self):
        """Initialize database from schema"""
        if not os.path.exists(self.db_path):
            print(f"[DB] Creating database at {self.db_path}")
            with sqlite3.connect(self.db_path) as conn:
                try:
                    with open(self.schema_path, 'r') as f:
                        conn.executescript(f.read())
                    conn.commit()
                    print("[DB] Database initialized")
                except Exception as e:
                    print(f"[DB] Error: {e}")
    
    def log_event(self, event_type: str, severity: str, details: dict, timestamp: Optional[datetime] = None) -> int:
        """Log an event"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "INSERT INTO events (event_type, severity, details, timestamp) VALUES (?, ?, ?, ?)",
                    (event_type, severity, json.dumps(details), timestamp or datetime.now())
                )
                conn.commit()
                return cursor.lastrowid
        except Exception as e:
            print(f"[DB] Error logging event: {e}")
            return -1
    
    def get_events(self, limit: int = 100, severity: Optional[str] = None, event_type: Optional[str] = None) -> List[Dict]:
        """Fetch events with filters"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                query = "SELECT * FROM events WHERE 1=1"
                params = []
                
                if severity:
                    query += " AND severity = ?"
                    params.append(severity)
                if event_type:
                    query += " AND event_type = ?"
                    params.append(event_type)
                
                query += " ORDER BY timestamp DESC LIMIT ?"
                params.append(limit)
                
                cursor.execute(query, params)
                return [dict(row) for row in cursor.fetchall()]
        except Exception as e:
            print(f"[DB] Error fetching events: {e}")
            return []
    
    def log_threat(self, threat_type: str, severity: str, process_name: str = None, 
                   file_path: str = None, action_taken: str = None) -> int:
        """Log a threat"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "INSERT INTO threats (threat_type, severity, process_name, file_path, action_taken) VALUES (?, ?, ?, ?, ?)",
                    (threat_type, severity, process_name, file_path, action_taken)
                )
                conn.commit()
                return cursor.lastrowid
        except Exception as e:
            print(f"[DB] Error logging threat: {e}")
            return -1
    
    def log_auth_attempt(self, username: str, success: bool, device_fingerprint: str = None) -> int:
        """Log auth attempt"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "INSERT INTO auth_log (username, success, device_fingerprint) VALUES (?, ?, ?)",
                    (username, success, device_fingerprint)
                )
                conn.commit()
                return cursor.lastrowid
        except Exception as e:
            print(f"[DB] Error logging auth: {e}")
            return -1
    
    def get_threats(self, limit: int = 50, hours: int = 24) -> List[Dict]:
        """Get threats from last N hours"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT * FROM threats WHERE datetime(timestamp) > datetime('now', ? || ' hours') ORDER BY timestamp DESC LIMIT ?",
                    (f'-{hours}', limit)
                )
                return [dict(row) for row in cursor.fetchall()]
        except Exception as e:
            print(f"[DB] Error fetching threats: {e}")
            return []
    
    def get_event_stats(self, hours: int = 24) -> Dict:
        """Get event statistics"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute(
                    "SELECT COUNT(*) FROM events WHERE datetime(timestamp) > datetime('now', ? || ' hours')",
                    (f'-{hours}',)
                )
                total = cursor.fetchone()[0]
                
                cursor.execute(
                    "SELECT COUNT(*) FROM threats WHERE severity='CRITICAL' AND datetime(timestamp) > datetime('now', ? || ' hours')",
                    (f'-{hours}',)
                )
                critical = cursor.fetchone()[0]
                
                return {"total_events": total, "critical_threats": critical}
        except Exception as e:
            print(f"[DB] Error: {e}")
            return {"total_events": 0, "critical_threats": 0}
    
    def export_events_csv(self, output_path: str, limit: int = 10000):
        """Export events to CSV"""
        try:
            import csv
            events = self.get_events(limit=limit)
            os.makedirs(os.path.dirname(output_path) if os.path.dirname(output_path) else ".", exist_ok=True)
            
            with open(output_path, 'w', newline='') as f:
                if events:
                    writer = csv.DictWriter(f, fieldnames=events[0].keys())
                    writer.writeheader()
                    writer.writerows(events)
                    print(f"[DB] Exported to {output_path}")
        except Exception as e:
            print(f"[DB] Export error: {e}")
    
    def get_event_count_by_type(self, hours: int = 24) -> Dict[str, int]:
        """Count events by type in last N hours"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """SELECT event_type, COUNT(*) as count FROM events
                       WHERE datetime(timestamp) > datetime('now', ? || ' hours')
                       GROUP BY event_type""",
                    (f'-{hours}',)
                )
                return {row[0]: row[1] for row in cursor.fetchall()} if cursor.fetchall() else {}
        except Exception as e:
            print(f"[DB] Error: {e}")
            return {}

    def get_events_by_hour(self, hours: int = 24) -> Dict[str, int]:
        """Get hourly event distribution"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """SELECT strftime('%H:00', timestamp) as hour, COUNT(*) as count 
                       FROM events
                       WHERE datetime(timestamp) > datetime('now', ? || ' hours')
                       GROUP BY hour
                       ORDER BY hour""",
                (f'-{hours}',)
            )
            return {row[0]: row[1] for row in cursor.fetchall()} if cursor.fetchall() else {}
        except Exception as e:
            print(f"[DB] Error: {e}")
        return {}

    def log_file_operation(self, operation: str, file_path: str, size_bytes: int, 
                      encrypted: bool = False) -> int:
        """Log file encryption/decryption operation"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """INSERT INTO protected_files 
                    (file_path, file_name, size_bytes, encrypted, encrypted_timestamp)
                    VALUES (?, ?, ?, ?, ?)""",
                    (file_path, file_path.split('\\')[-1], size_bytes, encrypted, 
                    datetime.now() if encrypted else None)
                )
                conn.commit()
            
            # Also log as event
            self.log_event(
                f"FILE_{operation.upper()}",
                "LOW",
                {"file": file_path, "size": size_bytes, "encrypted": encrypted}
            )
            return cursor.lastrowid
        except Exception as e:
            print(f"[DB] Error: {e}")
            return -1

    def get_encryption_stats(self, hours: int = 24) -> Dict:
        """Get encryption/decryption statistics"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Encrypted files
                cursor.execute(
                    """SELECT COUNT(*) FROM protected_files 
                    WHERE encrypted = 1 AND datetime(encrypted_timestamp) > datetime('now', ? || ' hours')""",
                    (f'-{hours}',)
                )
                encrypted_count = cursor.fetchone()[0]
                
                # Total size encrypted
                cursor.execute(
                    """SELECT SUM(size_bytes) FROM protected_files 
                    WHERE encrypted = 1 AND datetime(encrypted_timestamp) > datetime('now', ? || ' hours')""",
                    (f'-{hours}',)
                )
                total_size = cursor.fetchone()[0] or 0
                
                return {
                    "files_encrypted": encrypted_count,
                    "total_size_bytes": total_size,
                    "total_size_mb": round(total_size / (1024*1024), 2)
                }
        except Exception as e:
            print(f"[DB] Error: {e}")
            return {"files_encrypted": 0, "total_size_bytes": 0, "total_size_mb": 0}

    def get_threat_summary(self, hours: int = 24) -> Dict:
        """Get threat summary by type"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """SELECT threat_type, severity, COUNT(*) as count
                    FROM threats
                    WHERE datetime(timestamp) > datetime('now', ? || ' hours')
                    GROUP BY threat_type, severity""",
                    (f'-{hours}',)
                )
                result = cursor.fetchall()
                
                summary = {}
                for threat_type, severity, count in result:
                    if threat_type not in summary:
                        summary[threat_type] = {}
                    summary[threat_type][severity] = count
                
                return summary
        except Exception as e:
            print(f"[DB] Error: {e}")
            return {}