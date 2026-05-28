# 🛡️ ATLAS — Adaptive Threat Level Assessment & Security System

ATLAS is a modular, Blue Team-oriented security platform combining real-time monitoring, ML-based anomaly detection, and a modern GUI dashboard. Built for security teams who need actionable intelligence fast.

## 📋 Table of Contents
- [Overview](#overview)
- [Features](#features)
- [Project Structure](#project-structure)
- [Installation](#installation)
- [Usage](#usage)
- [Architecture](#architecture)
- [How ATLAS Works](#how-atlas-works)
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

## Architecture Diagram

```text
+----------------+   +----------------+   +----------------+   +---------------+
|  File Monitor  |   | Process Monitor|   | Network Monitor|   |  USB Monitor  |
+----------------+   +----------------+   +----------------+   +---------------+
        |                    |                    |                    |
        | (File Events)      | (Proc. Events)     | (Net. Events)      | (USB Events)
        v                    v                    v                    v
+-----------------------------------------------------------------------------+
|                                                                             |
|                             EVENT BUS (Central Queue)                         |
|                                                                             |
+-----------------------------------------------------------------------------+
        |                    |                    |                    |
        |                    |                    |                    |
+-------v--------+  +--------v---------+  +-------v--------+  +--------v-------+
|                |  |                  |  |                |  |                |
|  Threat Engine |  | Feature Extractor|  | Response Engine|  | Database Manager|
| (Rule-Based)   |  | (ML Vectorizer)  |  | (Containment)  |  | (Logging)      |
|                |  |                  |  |                |  |                |
+----------------+  +------------------+  +----------------+  +----------------+
        |                    |                    |                    |
        | (Rule Alerts)      | (Feature Vector)   | (Actions)          | (DB Writes)
        v                    v                    v                    v
+----------------+  +------------------+  +----------------+  +----------------+
|                |  |                  |  |                |  |                |
|  Dashboard UI  |  |   ML Detector    |  | - Kill Process |  |    Supabase    |
|                |  | (Anomaly Score)  |  | - Lock Vault   |  |    (Cloud)     |
|                |  |                  |  | - Email Alert  |  |                |
+----------------+  +------------------+  +----------------+  +----------------+
                             |
                             | (ML Anomaly Alert)
                             v
                   (Back to Event Bus)
```

## How ATLAS Works

ATLAS operates on a decoupled, event-driven architecture that allows for modular and parallel processing of security telemetry.

### 1. Real-Time Monitoring & Event Bus
-   Multiple monitors (`File`, `Process`, `Network`, `USB`) run in the background, watching for system activity.
-   When an event occurs (e.g., a file is created), the monitor publishes a standardized message to a central, thread-safe **Event Bus**.

### 2. Parallel Analysis
Once an event is on the bus, several subscribers process it simultaneously:
-   **Threat Engine**: Checks the event against a set of predefined rules (`monitor/rules.py`). If a rule is matched (e.g., a suspicious process name is detected), it generates a rule-based alert.
-   **Feature Extractor**: Collects all events over a 10-second window and converts them into a numerical **feature vector**. This vector is a snapshot of system behavior (e.g., `[files_modified, new_processes, cpu_usage, ...]`).
-   **Response Engine**: Listens for high-severity alerts and takes immediate action.
-   **Database Manager**: Logs key events to a secure Supabase backend.
-   **Risk Engine**: Consumes events to calculate a cumulative risk score that decays over time, providing a more nuanced assessment of the system's threat level than individual alerts alone.

### 3. ML Anomaly Detection
-   The **ML Detector** takes the latest feature vector from the extractor.
-   It uses a pre-trained **Isolation Forest** model to calculate an anomaly score. A lower score indicates a more unusual or anomalous pattern of behavior.
-   If the score crosses a dynamically calibrated threshold, the detector publishes a new `ML_ANOMALY` event back onto the bus, which can trigger higher-level alerts.

### 4. Automated Response & Containment
-   The **Response Engine** is the system's active defense layer. Based on the severity of an alert, it can terminate malicious processes, lock the **Vault**, blacklist attacker IPs, and send critical alert notifications via email.

## 📁 Project Structure

```text
ATLAS/
├── main.py                        # Main application entry point
├── requirements.txt
├── .env.example                   # Environment variable template
├── .gitignore
├── README.md
│
├── api/                           # Flask API for remote actions & WebAuthn
│   └── flask_app.py
│
├── auth/                          # Authentication logic
│   ├── biometric_manager.py
│   ├── otp_manager.py
│   └── session_manager.py
│
├── core/                          # Core services and state management
│   ├── runtime_state.py
│   ├── crypto_service.py
│   └── vault.py
│
├── dashboard/                     # GUI Layer (CustomTkinter)
│   ├── app.py                     # Main GUI application
│   ├── dashboard_tab.py
│   ├── logs_tab.py
│   ├── timeline_tab.py
│   └── ... (other UI tabs)
│
├── database/                      # Supabase integration layer
│   ├── client.py
│   ├── db_manager.py
│   └── schema.sql                 # Reference schema
│
├── monitor/                       # Real-time detection core
│   ├── event_bus.py
│   ├── file_monitor.py
│   ├── process_monitor.py
│   ├── network_monitor.py
│   ├── threat_engine.py           # Rule-based detection
│   ├── response_engine.py         # Automated containment
│   ├── ml_detector.py             # Anomaly detection
│   ├── risk_engine.py             # Cumulative risk scoring
│   └── feature_extractor.py       # ML feature vector creation
│
├── notifications/                 # Email alert system
│   └── email_sender.py
│
├── simulator/                     # Attack simulation scripts
│   ├── attack_sim.py              # Local simulation
│   ├── attack_remote.py
│   ├── sim_config.json
│
├── tests/                         # Unit and integration tests
│   ├── test_otp.py
│
├── assets/                        # (gitignored) Runtime assets
│
├── build_windows.bat
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
