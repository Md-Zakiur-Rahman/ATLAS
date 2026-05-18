# 🛡️ ATLAS — Adaptive Threat Level Assessment & Security System

ATLAS is a modular, Blue Team-oriented security platform combining real-time monitoring, ML-based anomaly detection, and a modern GUI dashboard. Built for security teams who need actionable intelligence fast.

## 📋 Table of Contents
- [Overview](#overview)
- [Features](#features)
- [Project Structure](#project-structure)
- [Installation](#installation)
- [Usage](#usage)
- [Architecture](#architecture)
- [Database](#database)
- [API](#api)
- [Tests](#tests)
- [Building for Windows](#building-for-windows)

## 🎯 Overview

ATLAS is a comprehensive Blue Team Threat Detection System that monitors, analyzes, and responds to security threats in real-time. It combines a CustomTkinter GUI dashboard with a Python backend featuring filesystem monitoring, ML anomaly scoring, network monitoring, Flask API, and Supabase cloud storage.

## ✨ Features

- **Real-Time Filesystem Monitoring** — watchdog-based file event capture
- **ML Anomaly Scoring** — Isolation Forest model with auto-calibrated thresholds
- **Process & System Inspection** — psutil-based process monitoring
- **Thread-Safe Event Bus** — decoupled pub/sub architecture
- **Hash-Chain Tamper Detection** — cryptographic log integrity verification
- **Network Monitoring** — connection tracking with IP threat flagging
- **Interactive Timeline Visualization** — matplotlib scatter with event detail cards
- **File Encryption/Decryption** — AES-256 secure file operations
- **Automated Report Generation** — PDF threat reports via ReportLab
- **Email & Notification Alerts** — Resend SMTP for security event alerts
- **HTTP API** — Flask with rate limiting and remote lock endpoint
- **Attack Simulator** — 5-phase attack simulation for demo and testing
- **Device Fingerprinting** — identify and track devices
- **Windows Installer** — standalone executable with InnoSetup

## 📁 Project Structure

```text
ATLAS/
├── main.py                        # Main entry point
├── attack_simulator.py            # Top-level attack simulator
├── requirements.txt
├── README.md
│
├── api/                           # Flask API
│   ├── flask_app.py
│   └── assets/
│       ├── feature_history.json
│       └── training_state.json
│
├── auth/                          # Auth helpers
│   ├── auth_controller.py
│   ├── otp_manager.py
│   └── session_manager.py
│
├── config/
│   ├── secrets.example.py
│   └── secrets.py                 # DO NOT COMMIT
│
├── core/
│   └── session.py
│
├── dashboard/                     # GUI Layer (CustomTkinter)
│   ├── app.py
│   ├── dashboard_tab.py
│   ├── logs_tab.py
│   ├── timeline_tab.py
│   ├── network_tab.py
│   ├── encrypt_tab.py
│   ├── report_tab.py
│   ├── settings_tab.py
│   ├── alerts.py
│   ├── animations.py
│   ├── ui_polish.py
│   └── pdf_generator.py
│
├── database/                      # Supabase layer
│   ├── client.py
│   ├── db_manager.py
│   └── schema.sql
│
├── monitor/                       # Detection core
│   ├── event_bus.py
│   ├── file_monitor.py
│   ├── process_monitor.py
│   ├── network_monitor.py
│   ├── usb_monitor.py
│   ├── threat_engine.py
│   ├── alert_manager.py
│   ├── response_engine.py
│   ├── ml_detector.py
│   ├── feature_extractor.py
│   ├── rename_log.py
│   ├── rules.py
│   └── models.py
│
├── notifications/                 # Email alerts
│   ├── manager.py
│   └── email_sender.py
│
├── simulator/                     # Attack simulation
│   ├── attack_sim.py
│   ├── attack_remote.py
│   ├── sim_config.json
│   └── test_targets/
│
├── logs/                          # Generated exports
│   ├── events_export_*.csv
│   └── threat_report_*.csv
│
├── tests/
│   ├── test_event_bus.py
│   ├── test_otp.py
│   ├── test_supabase.py
│   ├── test_threat_engine.py
│   └── test_verify.py
│
├── build_windows.bat
├── build_windows.ps1
└── build.spec
```

## 🚀 Installation

### Prerequisites
- Python 3.10+
- Internet connection (Supabase)
- Supabase account (free tier)

### Setup

1. **Clone the repository**
```bash
git clone https://github.com/Md-Zakiur-Rahman/ATLAS.git
cd ATLAS
```

2. **Install dependencies**
```bash
py -3.10 -m pip install -r requirements.txt
```

3. **Configure environment variables**
SUPABASE_URL=your_supabase_url
SUPABASE_KEY=your_supabase_key
RESEND_API_KEY=your_resend_key
SMTP_FROM=onboarding@resend.dev
4. **Initialize the database**
Run `database/schema.sql` in your Supabase project.

5. **Run the application**
```bash
py -3.10 main.py
```

## 💻 Usage

### Normal mode
```bash
py -3.10 main.py
```

### Training mode (ML baseline)
```bash
py -3.10 main.py --train --train-days 1.0
```

### Demo mode
Launch with demo credentials to explore all features without live Supabase.

## 🏗️ Architecture

| Layer | Technology | Purpose |
|---|---|---|
| UI | CustomTkinter 5.2.0 | Modern Python GUI |
| Database | Supabase (PostgreSQL) | Cloud storage |
| Backend | Python 3.10+ | Core logic |
| ML | scikit-learn | Isolation Forest anomaly detection |
| Reports | ReportLab | PDF generation |
| Visualization | Matplotlib | Charts & graphs |
| Alerts | Resend SMTP | Email notifications |
| API | Flask | Remote lock & auth endpoints |

## 🗄️ Database

### Supabase Tables
- `events` — event logging with hash-chaining
- `threats` — threat records and analysis
- `network_connections` — network activity logs
- `auth` — user authentication data
- `rename_log` — file rename tracking for ransomware detection
- `notifications` — security alert audit trail
- `otp_sessions` — OTP code tracking

## 🌐 API

```bash
python -m api.flask_app
```

| Endpoint | Method | Description |
|---|---|---|
| `/health` | GET | Health check |
| `/auth-verify` | POST | Verify credentials |
| `/auth-otp` | POST | Send OTP email |
| `/remote-lock` | GET | Trigger remote vault lock |

## 🧪 Tests

```bash
python -m unittest discover
```

## 📦 Building for Windows

```bash
python -m PyInstaller build.spec
# or
build_windows.bat
```

## 🔒 Security & Privacy

- Never commit `config/secrets.py` or `.env`
- Use service role key for Supabase backend only
- Rotate keys before sharing or publishing the repo
