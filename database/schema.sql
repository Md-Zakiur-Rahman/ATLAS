CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    details TEXT,
    category TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS threats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    threat_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    process_name TEXT,
    file_path TEXT,
    action_taken TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS auth_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT,
    success BOOLEAN,
    device_fingerprint TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS protected_files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    file_path TEXT UNIQUE,
    file_name TEXT,
    size_bytes INTEGER,
    encrypted BOOLEAN,
    encrypted_timestamp DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity);
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_timestamp_category ON events(timestamp, category);
CREATE INDEX IF NOT EXISTS idx_threats_timestamp ON threats(timestamp);
CREATE INDEX IF NOT EXISTS idx_auth_timestamp ON auth_log(timestamp);