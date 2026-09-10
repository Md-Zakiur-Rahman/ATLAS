# ATLAS

**Adaptive Threat Level Assessment & Security System** — a Windows-focused Blue Team desktop application for monitoring host activity, detecting suspicious behavior, and coordinating containment from one dashboard.

ATLAS collects file, process, USB, and network telemetry; sends it through a shared event bus; evaluates it with rules, risk scoring, and an Isolation Forest anomaly detector; and presents the result in a CustomTkinter analyst dashboard. Critical detections can trigger containment actions, alerts, and a remotely initiated vault lock.

> This is a defensive monitoring project. Run it only on systems and directories you own or are authorized to administer. The included simulators modify only their configured test directory, but should still be used in a disposable test environment.

## Features

- Real-time file, process, USB, and network monitoring
- Thread-safe event bus with rule-based threat detection and cumulative risk scoring
- ML baseline collection and Isolation Forest anomaly detection
- Automated response hooks for high-severity events: process termination, IP blocking, vault locking, and alerting
- CustomTkinter dashboard with timeline, network, event log, reports, settings, encryption/decryption, and whitelist views
- Password-plus-MFA login with email OTP; optional WebAuthn/passkey pairing through a QR flow
- Supabase persistence for authentication, events, alerts, biometric sessions, and remote-lock tokens
- Flask API with rate limiting, health check, MFA endpoints, passkey routes, and remote vault locking
- PDF incident reports and SMTP/Resend email notifications
- Local, configurable attack simulation for validating detection behavior

## Architecture

```text
File / Process / USB / Network monitors
                 |
                 v
           Event bus
     /       |        |        \
Rules   Feature extractor  Risk engine  Database / dashboard
             |
             v
        ML detector
             |
             v
       Response engine --> containment, alerts, vault lock
```

The normal launcher starts all monitors and analysis services in background threads, starts the Flask API, then runs the dashboard on the main thread. In baseline-training mode, it runs only the lightweight file, process, network, feature-extraction services; UI, API, alerts, and active containment are deliberately not started.

## Repository layout

```text
ATLAS/
├── main.py                 # Main runtime and ML training entry point
├── api/                    # Flask API and WebAuthn routes
├── auth/                   # Password, OTP, session, and biometric flows
├── config/                 # Logging and secrets template
├── core/                   # Vault, cryptography, keys, and runtime state
├── dashboard/              # CustomTkinter analyst interface and reports
├── database/               # Supabase client, persistence helpers, schema reference
├── monitor/                # Monitors, event bus, rules, ML, risk, and response engines
├── notifications/          # Email and notification delivery
├── simulator/              # Safe local/remote attack-simulation scripts
├── tests/                  # Runtime-focused unit/integration tests
├── attack_simulator.py     # Dynamic filesystem attack-behavior simulator
├── requirements.txt
├── build.spec              # PyInstaller specification
└── setup.iss               # Inno Setup installer definition
```

`blue_team_system/` is a separate, older prototype with its own tests and requirements; the supported runtime documented here is the top-level `main.py` application.

## Requirements

- Windows 10/11 (USB monitoring, Windows notifications, and the build scripts are Windows-specific)
- Python 3.10 or later
- A Supabase project and credentials
- Internet access when using Supabase, Resend email, IP enrichment, or a public biometric pairing tunnel

Install the declared packages:

```powershell
py -3.10 -m pip install -r requirements.txt
```

The launcher/API also import these runtime packages, which are not currently listed in `requirements.txt`:

```powershell
py -3.10 -m pip install flask flask-limiter schedule scikit-learn Pillow
```

## Configuration

Create a `.env` file beside `main.py`. Start from the variable names in [`config/secrets.example.py`](config/secrets.example.py):

```dotenv
SUPABASE_URL=https://your-project-ref.supabase.co
SUPABASE_KEY=your_supabase_key

# Needed for email OTP and threat notifications
RESEND_API_KEY=your_resend_api_key
SMTP_FROM=security@example.com

# Recommended when exposing the Flask service
FLASK_SECRET_KEY=use-a-long-random-secret
```

Optional SMTP settings are `SMTP_HOST` (default: `smtp.resend.com`), `SMTP_PORT` (default: `465`), and `SMTP_USER` (default: `resend`).

For the QR/WebAuthn flow, configure the values expected by `auth/biometric_manager.py` and make the local API reachable via HTTPS. If `NGROK_DOMAIN` is set and `ngrok` is on `PATH`, the normal launcher attempts to start an `ngrok http 80` tunnel. These integrations are optional; the dashboard continues without biometric routes if their dependencies or configuration are unavailable.

### Supabase

The runtime requires `SUPABASE_URL` and `SUPABASE_KEY` at startup. Apply the schema appropriate to your Supabase deployment before registering users. [`database/schema.sql`](database/schema.sql) is a reference schema for local-style event tables; the active application also expects Supabase tables used by the authentication, OTP, notification, biometric, and remote-lock flows. Review those queries and apply your project migration/schema before using the application against production data.

Never commit `.env`, service-role keys, or generated vault material.

## Run ATLAS

From this directory:

```powershell
py -3.10 main.py
```

This launches the monitoring runtime, a Flask service at `0.0.0.0:80`, and the dashboard. The login screen supports user registration, password verification followed by email OTP, and—when configured—passkey approval.

The API health endpoint is available at:

```text
GET http://localhost/health
```

Do not expose the API directly to the internet. Place it behind a properly configured HTTPS reverse proxy or use a controlled tunnel for the biometric workflow.

## ML baseline training

Collect representative, benign activity before relying on ML anomaly scores:

```powershell
py -3.10 main.py --baseline-train --train-days 1
```

`--train` currently uses the same collection-only training runtime. The process periodically saves feature history and trains a model when the collection interval completes; interrupting it saves collected history and trains only when at least 60 samples are available. Normal mode retains rule-based detection even without a trained model.

## Testing and simulation

Run the runtime test suite from this directory:

```powershell
py -3.10 -m unittest discover -s tests
```

Some tests and imports require valid Supabase configuration. The legacy prototype test suite under `blue_team_system/tests/` uses `pytest` and is separate from the main runtime.

To exercise the detector using the configurable local simulation:

```powershell
py -3.10 simulator/attack_sim.py
```

Before running it, inspect [`simulator/sim_config.json`](simulator/sim_config.json). It performs localhost port checks, repeated authentication requests, writes synthetic files to `attack_folder`, renames generated files to simulate ransomware behavior, and attempts the configured C2 connection. Renamed simulator files are restored after `revert_delay_seconds`; generated test files are not automatically removed.

For a randomized filesystem-behavior demo, use:

```powershell
py -3.10 attack_simulator.py --path D:\ATLAS_TEST --intensity medium
```

Use a dedicated test directory—never a directory containing real files.

## API overview

| Endpoint | Method | Purpose |
| --- | --- | --- |
| `/health` | `GET` | Runtime health response |
| `/auth-verify` | `POST` | Verifies password; MFA remains required |
| `/auth-otp` | `POST` | Sends an email OTP |
| `/remote-lock?token=…` | `GET` | Consumes a one-time remote-lock token |
| `/biometric/pair/<qr_token>` | `GET` | QR pairing page when WebAuthn is enabled |
| `/webauthn/*` | `POST` | Passkey registration/authentication flow |

The API uses an in-memory rate limiter. It is intended for the local application and controlled biometric tunnel, not as a public multi-instance web service.

## Build for Windows

Install PyInstaller, then run either build entry point:

```powershell
py -3.10 -m pip install pyinstaller
py -3.10 -m PyInstaller build.spec
# or
.\build_windows.ps1
```

`build.spec` currently produces `dist/BlueTeamSystem.exe`. Review and align [`setup.iss`](setup.iss) with that artifact name before compiling an Inno Setup installer, since its file entries currently refer to `ATLAS.exe`.

## Security notes

- Use non-production data and a test host while evaluating automated containment.
- Treat remote-lock URLs as one-time secrets; they lock the vault for their associated user.
- Supply a strong `FLASK_SECRET_KEY`; the development fallback is not suitable for deployment.
- Review detection rules, monitored paths, process allowlists, and response behavior in `monitor/` before enabling it on a production workstation.

## License

No license file is currently included. Do not assume permission to redistribute or use the project beyond the repository owner’s terms.
