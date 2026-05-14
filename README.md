# Blue Team Threat Detection System

A Python-based desktop security application combining AES-256 file encryption
with real-time defensive monitoring, built for a 5-day cybersecurity sprint.

## Team
- Member A — Security Core & Encryption Engine
- Member B — Monitoring, Detection & Alert Engine
- Member C — Dashboard, Logging & Reporting

## Stack
- Python 3.10+
- CustomTkinter — GUI
- cryptography — AES-256-GCM encryption
- watchdog — real-time file monitoring
- psutil — process monitoring
- SQLite3 — event logging
- bcrypt — password hashing

## Setup

1. Clone the repo:
   git clone https://github.com/.../ATLAS.git
   cd ATLAS/blue_team_system

2. Create a virtual environment:
   python -m venv venv
   venv\Scripts\activate

3. Install dependencies:
   pip install -r requirements.txt

4. Run the app:
   python main.py

## Running Tests

From inside blue_team_system/:
   pytest tests/ -v

## Dev Mode
To bypass device fingerprint checking during development, pass dev_mode=True
to verify_auth() and verify_profile(). Never use this in production.

## Security Notes
- The encryption key is never stored on disk — only the salt is saved in vault.keyfile
- Back up vault.keyfile — losing it means losing access to encrypted files
- Honeypot files are tracked in .honeypot_registry — do not delete this file
- auth_profiles.json stores bcrypt hashes only — never plaintext passwords

## .gitignore
Make sure these are never committed:
   __pycache__/, *.pyc, *.db, *.key, .env, venv/, dist/, build/, auth.dat,
   auth_profiles.json, vault.keyfile, vault.locked, notes.vault