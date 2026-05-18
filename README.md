# ATLAS — Adaptive Threat Level Assessment & Security System

ATLAS is a modular, Blue Team-oriented security platform providing monitoring, detection, and response tooling. This repository contains the Detection & Monitoring core plus supporting API, auth, notification, database, and simulator components.

**Quick links**
- **Main launcher:** [main.py](main.py)
- **API:** [api/flask_app.py](api/flask_app.py)
- **Configuration example:** [config/secrets.example.py](config/secrets.example.py)
- **Current config (local):** [config/secrets.py](config/secrets.py) — DO NOT commit production secrets

## Key Features

- Real-time filesystem monitoring (watchdog)
- Process and system inspection (psutil)
- Thread-safe event bus and threat severity classification
- ML-based anomaly scoring and training lifecycle (monitor/ml_detector.py)
- HTTP API with rate limiting and remote lock endpoint
- Simulator tooling for testing attack scenarios

## Repository layout

- [monitor/](monitor): core monitors, detectors, threat engine, feature extractor
- [api/](api): Flask API and endpoints
- [auth/](auth): authentication helpers, OTP and session management
- [database/](database): Supabase client and DB manager
- [notifications/](notifications): email sending and notification manager
- [simulator/](simulator): attacker simulation scripts and test targets
- [tests/](tests): unit tests (unittest)

## File structure

A high-level view of the repository layout:

```text
ATLAS/
	attack_simulator.py
	main.py
	README.md
	requirements.txt
	test_ml.py
	api/
		__init__.py
		flask_app.py
		assets/
			feature_history.json
			training_state.json
	auth/
		auth_controller.py
		otp_manager.py
		session_manager.py
	config/
		secrets.example.py
		secrets.py
	core/
		session.py
	database/
		__init__.py
		client.py
		db_manager.py
	monitor/
		__init__.py
		alert_manager.py
		event_bus.py
		feature_extractor.py
		file_monitor.py
		ml_detector.py
		models.py
		network_monitor.py
		process_monitor.py
		rename_log.py
		response_engine.py
		rules.py
		threat_engine.py
		usb_monitor.py
	notifications/
		__init__.py
		email_sender.py
		manager.py
		test_send.py
	simulator/
		__init__.py
		attack_remote.py
		attack_sim.py
		sim_config.json
		test_targets/
			sensitive_data_0.txt
			sensitive_data_1.txt
			...
	tests/
		test_event_bus.py
		test_otp.py
		test_supabase.py
		test_threat_engine.py
		test_verify.py
```

## Prerequisites

- Python 3.10
- Install dependencies:

```bash
py -3.10 -m pip install -r requirements.txt
```

Note: `requirements.txt` may contain project-specific GUI or optional deps; install in a virtual environment.

## Configuration

Copy or set environment variables based on [config/secrets.example.py](config/secrets.example.py). Important configuration keys:

- `SUPABASE_URL` and `SUPABASE_KEY` (Supabase project)
- `RESEND_API_KEY` or SMTP settings for email OTP delivery
- `SMTP_FROM` default sender address

Do not commit real keys into the repository. Use environment variables or an ignored `config/secrets.py` for local development.

## Running ATLAS (monitoring)

Start the main launcher:

```bash
py -3.10 main.py
```

Training mode (collect baseline telemetry and train ML model):

```bash
py -3.10 main.py --train --train-days 1.0
```

Notes:
- The launcher starts file, process, and USB monitors, the feature extractor, and the ML lifecycle.
- If no calibrated ML model is present the system runs in rule-based detection mode and logs a warning with instructions to run the `--train` flag.

## API

Start the Flask API locally:

```bash
python -m api.flask_app
```

Main endpoints:

- `GET /health` — basic health check
- `POST /auth-verify` — body JSON `{ "email": "...", "password": "..." }` (verifies credentials)
- `POST /auth-otp` — body JSON `{ "email": "..." }` (sends OTP email)
- `GET /remote-lock?token=...` — consume OTP session and trigger remote vault lock

The API applies rate-limiting and publishes security events to the internal event bus on notable actions (auth failures, rate limit breaches, remote locks).

## Simulator

Simulator scripts under [simulator/](simulator) and top-level `attack_simulator.py` provide attack scenarios and test targets located in `simulator/test_targets/`.

## Tests

Unit tests use the standard library `unittest`. Run tests with:

```bash
python -m unittest discover
```

Or run an individual test file, e.g.:

```bash
python -m unittest tests.test_event_bus
```

## Development notes

- ML telemetry and model state are managed by `monitor/ml_detector.py` and persisted by the project (see `api/assets/feature_history.json` and `api/assets/training_state.json`).
- Logging is configured in `main.py` and `api/flask_app.py` — adjust levels as needed for debugging.
- The event bus (`monitor/event_bus.py`) is the primary integration point for monitors, detectors, and response components.

## Security & privacy

- Remove or rotate the keys found in `config/secrets.py` before publishing or sharing the repository.
- Use least-privileged service keys for Supabase and email services.

## Contributing

- Fork the repo, create a branch, and open a PR with a short description of changes.
- Run unit tests and linters before submitting.

## Integration & Merge Guide (for Member A / C integration)

This section helps when merging this Detection & Monitoring core (Member B) with other branches (A, C). Follow these steps to minimize conflicts and preserve clear boundaries.

- **Keep interfaces stable:** only change public interfaces after coordinating across teams. Public interfaces include:
	- Event bus message schema and published event `type` values (see `monitor/event_bus.py`).
	- HTTP API endpoints and request/response shapes (see `api/flask_app.py`).
	- Configuration keys in `config/secrets.example.py`.
- **Small, focused PRs:** prefer multiple small PRs over one large merge to make reviews and conflict resolution easier.
- **Merge workflow (recommended):**
	1. Fetch latest from `main` (or target integration branch) and rebase your feature branch: `git fetch origin && git rebase origin/main`.
 2. Resolve conflicts locally, run unit tests, and verify the ML training path if affected.
 3. Push and open a PR; request review from owners of Member A and Member C changes.
- **Conflict priorities:** when an API/schema conflict exists, prefer keeping backwards-compatible behavior and add migration steps in the PR notes.
- **Testing after merge:** run `py -3.10 main.py --train --train-days 0.01` (short run) and `python -m unittest discover` to validate runtime and tests.

### Public-interface checklist

- `monitor/event_bus.py`: list of event `type` strings consumed by `ThreatEngine` and `response_engine`.
- `monitor/ml_detector.py`: model persistence format and `feature_history` shape.
- `api/flask_app.py`: endpoints `POST /auth-verify`, `POST /auth-otp`, `GET /remote-lock` and rate limiting behavior.
- `config/secrets.example.py`: ensure new config keys are added here and not only in `config/secrets.py`.

### Pre-merge checklist

- [ ] Rebase onto target branch and resolve conflicts locally.
- [ ] Run `python -m unittest discover` and fix failing tests.
- [ ] Verify API endpoints with a local run of the Flask app.
- [ ] Verify ML training path if changes touch `monitor/ml_detector.py` or `monitor/feature_extractor.py`.
- [ ] Add migration notes to PR if public interfaces changed.

---

---

If you'd like, I can also:
- add a small usage snippet showing a recommended development setup (venv + pip)
- add environment-variable examples or a `.env.sample`
- run the unit tests locally and report results

Files updated: [README.md](README.md)
