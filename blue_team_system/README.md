# Blue Team Threat Detection System v3.0

A Python-based desktop security application combining AES-256 file encryption
with real-time defensive monitoring, ML anomaly detection, and Telegram alerts.
Built as a 10-day cybersecurity sprint.

## Team
- Member A — Security Core & Encryption Engine
- Member B — Monitoring, ML & Alert Engine
- Member C — Dashboard, GUI & Installer

## Stack
- Python 3.10+
- CustomTkinter — GUI
- cryptography — AES-256-GCM encryption
- watchdog — real-time file monitoring
- psutil — process & network monitoring
- SQLite3 — hash-chained event logging
- bcrypt — password hashing
- pyotp — TOTP / OTP generation
- Flask — remote lock endpoint
- scikit-learn — Isolation Forest ML detector
- PyInstaller + Inno Setup — Windows installer

## System Requirements
- Windows 10/11 or Ubuntu 20.04+
- Python 3.10 or higher
- 200MB RAM minimum during monitoring
- Internet connection for Telegram alerts

## Setup

1. Clone the repo:
   git clone https://github.com/.../ATLAS.git
   cd ATLAS/blue_team_system

2. Install dependencies:
   pip install -r requirements.txt

3. Run the app:
   python main.py

   First launch shows the setup wizard automatically.

4. Auto-start on boot:
   Enabled automatically by the setup wizard.
   Toggle in Settings tab inside the app.

## Running Tests

From inside blue_team_system/:
   pytest tests/ -v --ignore=tests/demo_attack.py

## Running the Demo Attack

From inside blue_team_system/:
   python tests/demo_attack.py

## Remote Lock (ngrok)

1. Start the app: python main.py
2. In a separate terminal: ngrok http 5000
3. Copy the ngrok URL and save it:
   echo https://xxxx.ngrok.io > .ngrok_url
4. On CRITICAL alert, Telegram sends a one-click lock URL

## Security Notes
- Encryption key is never stored — only the salt is saved in vault.keyfile
- Back up vault.keyfile — losing it means losing access to encrypted files
- Honeypot files are tracked in .honeypot_registry — do not delete
- auth_profiles.json stores bcrypt hashes only — never plaintext
- Log chain is verified on every startup — tamper triggers CRITICAL alert

## .gitignore
Ensure these are never committed:
   __pycache__/, *.pyc, *.db, .env, venv/, dist/, build/,
   auth.dat, auth_profiles.json, vault.keyfile, vault.locked,
   notes.vault, registered_user.json, .ngrok_url, *.keyfile

## Known Issues
- Windows Hello biometric requires admin privileges on some machines
- ngrok free tier has connection limits — use a fixed domain for production
- ML model requires 10-minute baseline before scoring is accurate

## Version History
- v1.0 — Days 1-5: Core encryption, monitoring MVP
- v2.0 — Days 6-8: ML detection, full auth, Telegram, remote lock
- v3.0 — Days 9-10: Hash-chain logs, whitelist, auto-start, installer