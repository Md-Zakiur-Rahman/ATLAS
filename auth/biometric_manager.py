from __future__ import annotations

import base64
import os
import json
import secrets
import socket
import subprocess
import threading
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional
from urllib.parse import urlparse

import requests

from config.logging_config import get_logger
from core.runtime_state import runtime_state
from database.client import supabase
from monitor.event_bus import event_bus

logger = get_logger("auth")
bio_file_logger = get_logger("biometric")

def log_bio_event(event_data: Dict[str, Any]):
    """Formats and logs a biometric event to the dedicated file."""
    try:
        timestamp = f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}]"
        lines = [timestamp]
        for key, value in event_data.items():
            lines.append(f"{key.upper()}={value}")
        bio_file_logger.info("\n".join(lines) + "\n")
    except Exception as e:
        logger.error("Failed to write to biometric log file: %s", e)

WEBAUTHN_AVAILABLE = False
try:
    from webauthn import (
        generate_authentication_options,
        generate_registration_options,
        options_to_json,
        verify_authentication_response,
        verify_registration_response,
    )
    from webauthn.helpers import bytes_to_base64url
    from webauthn.helpers.structs import (
        AuthenticationCredential,
        AuthenticatorSelectionCriteria,
        PublicKeyCredentialDescriptor,
        RegistrationCredential,
        ResidentKeyRequirement,
        UserVerificationRequirement,
    )
    import hashlib
    WEBAUTHN_AVAILABLE = True
    logger.info("WebAuthn package loaded successfully.")
except ImportError:
    logger.warning(
        "WebAuthn package not found or is incompatible. "
        "Biometric authentication will be disabled. "
        "Install with: pip install webauthn"
    )


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)



def _iso(ts: datetime) -> str:
    return ts.isoformat()



def _parse_iso(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except Exception:
        return None



def _b64_to_bytes(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode((value + padding).encode("ascii"))


class BiometricManager:
    def __init__(self) -> None:
        self.max_failed_attempts = 3
        self.flask_port = 80
        self.base_auth_url: Optional[str] = None
        self.rp_id: Optional[str] = None
        self.ngrok_process: Optional[subprocess.Popen] = None
        self.ngrok_lock = threading.RLock()
        self.pending_challenges: Dict[str, Dict[str, Any]] = {}

        

    # ------------------- tunnel -------------------
    def _detect_lan_ipv4(self) -> str:
        if not WEBAUTHN_AVAILABLE:
            return "127.0.0.1"
        candidate = "127.0.0.1"
        try:
            probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            probe.connect(("8.8.8.8", 80))
            candidate = probe.getsockname()[0]
            probe.close()
        except Exception:
            pass
        return candidate

    def _set_origin(self, url: str) -> None:
        parsed = urlparse(url)
        self.base_auth_url = f"{parsed.scheme}://{parsed.netloc}"
        self.rp_id = parsed.hostname
        log_bio_event(
            {
                "event": "WEBAUTHN_ORIGIN_CONFIGURED",
                "rp_id": self.rp_id,
                "origin": self.base_auth_url,
            }
        )
        logger.info("WebAuthn origin configured | BASE_AUTH_URL=%s RP_ID=%s", self.base_auth_url, self.rp_id)

    def _ngrok_https_url(self) -> Optional[str]:
        if not WEBAUTHN_AVAILABLE:
            return None
        try:
            response = requests.get("http://127.0.0.1:4040/api/tunnels", timeout=3)
            data = response.json()
            for tunnel in data.get("tunnels", []):
                pub = str(tunnel.get("public_url", ""))
                if pub.startswith("https://"):
                    return pub
        except Exception as error:
            logger.warning("Failed to query ngrok tunnels: %s", error)
        return None

    def ensure_secure_tunnel(self) -> tuple[bool, str]:
        if not WEBAUTHN_AVAILABLE:
            return False, "Biometric feature unavailable: webauthn package missing."

        # Step 1 — check if ngrok is already running (manual or previous auto-start)
        logger.info("Tunnel check: looking for existing ngrok tunnel...")
        existing = self._ngrok_https_url()
        if existing:
            logger.info("Tunnel check: found existing tunnel: %s", existing)
            self._set_origin(existing)
            return True, existing

        # Step 2 — kill any dead/zombie ngrok process from a previous run
        if self.ngrok_process and self.ngrok_process.poll() is not None:
            logger.info("Cleaning up dead ngrok process from previous run.")
            self.ngrok_process = None

        # Step 3 — start ngrok fresh
        try:
            logger.info("Auto-starting ngrok on port %d...", self.flask_port)
            log_bio_event({"event": "NGROK_STARTUP", "port": self.flask_port})
            self.ngrok_process = subprocess.Popen(
                ["ngrok", "http", str(self.flask_port)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            logger.info("ngrok started with PID %d", self.ngrok_process.pid)
        except FileNotFoundError:
            msg = "ngrok not found in PATH. Install ngrok and add to PATH."
            logger.error(msg)
            return False, msg
        except Exception as error:
            msg = f"ngrok failed to start: {error}"
            logger.error(msg)
            return False, msg

        # Step 4 — wait for tunnel to be ready with fixed retry cadence
        # Initial wait for ngrok to initialize before first poll
        time.sleep(2)

        for attempt in range(1, 11):
            logger.debug("Polling ngrok API attempt %d/10...", attempt)
            url = self._ngrok_https_url()
            if url:
                self._set_origin(url)
                log_bio_event({"event": "NGROK_URL_FETCHED", "url": url})
                logger.info("Tunnel ready on attempt %d: %s", attempt, url)
                return True, url

            # Check if ngrok died during startup
            if self.ngrok_process.poll() is not None:
                msg = (
                    "ngrok exited during startup. "
                    "Check ngrok is authenticated: ngrok config add-authtoken YOUR_TOKEN"
                )
                logger.error(msg)
                return False, msg

            time.sleep(1.5)

        # Step 5 — timeout, kill the process we started and report failure
        logger.error("Tunnel startup timed out after 17 seconds.")
        self.cleanup_tunnel()
        return False, (
            "Failed to establish secure tunnel. "
            "Start manually: ngrok http 80"
        )

    def cleanup_tunnel(self) -> None:
        if self.ngrok_process:
            try:
                self.ngrok_process.terminate()
                self.ngrok_process.wait(timeout=3)
                logger.info("ngrok process terminated cleanly.")
            except Exception:
                try:
                    self.ngrok_process.kill()
                    logger.info("ngrok process killed forcefully.")
                except Exception as error:
                    logger.warning("Failed to kill ngrok process: %s", error)
            finally:
                self.ngrok_process = None
        self.base_auth_url = None
        self.rp_id = None
        log_bio_event({"event": "NGROK_CLEANUP"})

    # ------------------- devices/sessions -------------------
    def has_trusted_device(self, email: str) -> bool:
        if not WEBAUTHN_AVAILABLE:
            return False
        if not email:
            return False
        try:
            result = (
                supabase.table("biometric_devices")
                .select("id")
                .eq("email", email)
                .eq("trusted", True)
                .limit(1)
                .execute()
            )
            return bool(result.data)
        except Exception:
            return False

    def create_session(self, email: str) -> Dict[str, Any]:
        if not WEBAUTHN_AVAILABLE:
            raise RuntimeError("Biometric feature unavailable: webauthn package missing.")
        logger.info("STEP 1: create_session started for email=%s", email)
        logger.info("STEP 2: ensuring secure tunnel...")
        ok, tunnel_or_error = self.ensure_secure_tunnel()
        if not ok:
            raise RuntimeError(tunnel_or_error)
        logger.info("STEP 3: tunnel verified, URL: %s", self.base_auth_url)

        logger.info("STEP 4: creating session and challenge...")
        trusted_exists = self.has_trusted_device(email)
        status = "PENDING_AUTH" if trusted_exists else "PENDING_REGISTRATION"
        session_token = secrets.token_urlsafe(24)
        qr_token = secrets.token_urlsafe(24)
        expires_at = _utcnow() + timedelta(minutes=5)

        row = {
            "email": email,
            "session_token": session_token,
            "qr_token": qr_token,
            "status": status,
            "expires_at": _iso(expires_at),
        }
        supabase.table("biometric_sessions").insert(row).execute()

        log_bio_event(
            {
                "event": "WEBAUTHN_SESSION_CREATED",
                "email": email,
                "flow": "auth" if trusted_exists else "registration",
                "qr_token": qr_token,
            }
        )
        self.pending_challenges[session_token] = {
            "challenge": None,
            "used": False,
            "flow": "auth" if trusted_exists else "registration",
            "created_at": time.time(),
            "origin": self.base_auth_url,
            "rp_id": self.rp_id,
        }

        runtime_state.set_nested(
            "biometric_state",
            {
                "trusted_device": trusted_exists,
                "pairing_state": status.lower(),
                "session_token": session_token,
                "expires_at": row["expires_at"],
                "base_auth_url": self.base_auth_url,
                "rp_id": self.rp_id,
                "tunnel_state": "online",
            },
        )
        row["flow"] = "approval" if trusted_exists else "registration"
        row["base_auth_url"] = self.base_auth_url
        logger.info("STEP 5: session creation complete.")
        return row

    def get_pairing_url(self, qr_token: str) -> str:
        if not self.base_auth_url:
            raise RuntimeError("Secure tunnel not configured")
        url = f"{self.base_auth_url}/biometric/pair/{qr_token}"
        log_bio_event(
            {
                "event": "QR_URL_GENERATED",
                "url": url,
            }
        )
        return url

    def get_session_by_token(self, session_token: str) -> Optional[Dict[str, Any]]:
        try:
            result = (
                supabase.table("biometric_sessions")
                .select("*")
                .eq("session_token", session_token)
                .limit(1)
                .execute()
            )
            rows = result.data or []
            return rows[0] if rows else None
        except Exception:
            return None

    def get_session_by_qr(self, qr_token: str) -> Optional[Dict[str, Any]]:
        try:
            result = (
                supabase.table("biometric_sessions")
                .select("*")
                .eq("qr_token", qr_token)
                .limit(1)
                .execute()
            )
            rows = result.data or []
            return rows[0] if rows else None
        except Exception:
            return None

    def _mark_expired_if_needed(self, row: Dict[str, Any]) -> bool:
        expires_at = _parse_iso(row.get("expires_at"))
        if expires_at and _utcnow() > expires_at:
            try:
                (
                    supabase.table("biometric_sessions")
                    .update({"status": "EXPIRED"})
                    .eq("id", row.get("id"))
                    .execute()
                )
            except Exception:
                pass
            runtime_state.set_nested("biometric_state", {"pairing_state": "expired"})
            # TODO: call biometric_manager.cleanup_tunnel() when QR dialog is closed or session expires
            return True
        return False

    def check_session_status(self, session_token: str) -> str:
        row = self.get_session_by_token(session_token)
        if not row:
            return "missing"
        if self._mark_expired_if_needed(row):
            return "expired"

        status = (row.get("status") or "PENDING_AUTH").upper()
        if status in {"APPROVED", "COMPLETED"}:
            runtime_state.set_nested("biometric_state", {"pairing_state": "approved"})
            return "approved"
        if status == "SCANNED":
            return "scanned"
        if status in {"DENIED", "REJECTED", "FAILED"}:
            runtime_state.set_nested("biometric_state", {"pairing_state": "rejected"})
            return "rejected"
        if status == "EXPIRED":
            return "expired"
        return "pending"

    # ------------------- webauthn start/finish -------------------
    def _registered_credentials(self, email: str) -> list[PublicKeyCredentialDescriptor]:
        if not WEBAUTHN_AVAILABLE:
            return []
        result = (
            supabase.table("biometric_devices")
            .select("credential_id")
            .eq("email", email)
            .eq("trusted", True)
            .execute()
        )
        rows = result.data or []
        output: list[PublicKeyCredentialDescriptor] = []
        for row in rows:
            credential_id = row.get("credential_id")
            if credential_id:
                output.append(PublicKeyCredentialDescriptor(id=_b64_to_bytes(str(credential_id))))
        return output

    def _origin_mismatch_for_email(self, email: str) -> bool:
        if not WEBAUTHN_AVAILABLE:
            return False
        result = (
            supabase.table("biometric_devices")
            .select("transports")
            .eq("email", email)
            .eq("trusted", True)
            .limit(1)
            .execute()
        )
        rows = result.data or []
        if not rows:
            return False
        try:
            meta = json.loads(rows[0].get("transports") or "{}")
        except Exception:
            return False
        stored_rp = meta.get("rp_id")
        return bool(stored_rp and self.rp_id and stored_rp != self.rp_id)

    def webauthn_register_start(self, session_token: str) -> Dict[str, Any]:
        if not WEBAUTHN_AVAILABLE:
            raise RuntimeError("Biometric feature unavailable: webauthn package missing.")
        session = self.get_session_by_token(session_token)
        if not session:
            raise ValueError("SESSION_NOT_FOUND")
        if self._mark_expired_if_needed(session):
            raise ValueError("SESSION_EXPIRED")
        if not self.base_auth_url or not self.rp_id:
            raise ValueError("ORIGIN_NOT_READY")

        email = session.get("email")
        user_id = hashlib.sha256(email.encode("utf-8")).digest()[:32]
        options = generate_registration_options(
            rp_id=self.rp_id,
            rp_name="ATLAS Cyber Defense",
            user_id=user_id,
            user_name=email,
            user_display_name=email,
            timeout=60000,
            authenticator_selection=AuthenticatorSelectionCriteria(
                resident_key=ResidentKeyRequirement.REQUIRED,
                user_verification=UserVerificationRequirement.REQUIRED,
            ),
            exclude_credentials=self._registered_credentials(email),
        )
        payload = json.loads(options_to_json(options))
        self.pending_challenges[session_token] = {
            **self.pending_challenges.get(session_token, {}),
            "challenge": payload["challenge"],
            "used": False,
            "flow": "registration",
            "origin": self.base_auth_url,
            "rp_id": self.rp_id,
            "created_at": time.time(),
        }
        logger.info("WebAuthn registration challenge created for %s", email)
        log_bio_event(
            {
                "event": "WEBAUTHN_REGISTER_START",
                "email": email,
                "rp_id": self.rp_id,
                "challenge_b64": payload["challenge"],
            }
        )
        return payload

    def webauthn_register_finish(self, session_token: str, credential_payload: Dict[str, Any], device_name: str) -> tuple[bool, str]:
        if not WEBAUTHN_AVAILABLE:
            raise RuntimeError("Biometric feature unavailable: webauthn package missing.")
        session = self.get_session_by_token(session_token)
        if not session:
            return False, "SESSION_NOT_FOUND"
        if self._mark_expired_if_needed(session):
            return False, "SESSION_EXPIRED"

        pending = self.pending_challenges.get(session_token) or {}
        if pending.get("used"):
            logger.warning("Replay attempt blocked for registration session=%s", session_token[:8])
            return False, "REPLAY_BLOCKED"
        challenge = pending.get("challenge")
        if not challenge:
            logger.warning("Registration failed for session=%s: challenge missing from state.", session_token[:8])
            return False, "CHALLENGE_MISSING"

        expected_rp_id = pending.get("rp_id") or self.rp_id
        expected_origin = pending.get("origin") or self.base_auth_url
        logger.info(
            "Verifying registration for session=%s | email=%s | rp_id=%s",
            session_token[:8],
            session.get("email"),
            expected_rp_id,
        )
        log_bio_event(
            {
                "event": "WEBAUTHN_REGISTER_VERIFY",
                "email": session.get("email"),
                "rp_id": expected_rp_id,
                "origin": expected_origin,
                "credential_id": credential_payload.get("id"),
                "expected_challenge_b64": challenge,
            }
        )
        # Add detailed payload logging for debugging
        try:
            client_data_json_b64 = credential_payload.get("response", {}).get("clientDataJSON")
            if client_data_json_b64:
                client_data_json = _b64_to_bytes(client_data_json_b64).decode("utf-8")
                client_challenge = json.loads(client_data_json).get("challenge")
                log_bio_event(
                    {
                        "event": "WEBAUTHN_CLIENT_CHALLENGE",
                        "client_challenge_b64": client_challenge,
                    }
                )
        except Exception:
            pass

        try:
            verification = verify_registration_response(credential=credential_payload, expected_challenge=_b64_to_bytes(challenge), expected_rp_id=expected_rp_id, expected_origin=expected_origin, require_user_verification=True)
        except Exception as error:
            logger.exception("WebAuthn registration verification failed for session=%s: %s", session_token[:8], error)
            log_bio_event(
                {
                    "event": "WEBAUTHN_REGISTER_VERIFY",
                    "email": session.get("email"),
                    "status": "FAILED",
                    "error_type": str(error.__class__.__name__),
                    "error_details": str(error),
                }
            )
            return False, "VERIFY_FAILED"

        credential_id_b64 = bytes_to_base64url(verification.credential_id)
        row = {
            "email": session.get("email"),
            "device_id": secrets.token_hex(12),
            "device_name": (device_name or "Passkey Device").strip()[:80],
            "public_key": bytes_to_base64url(verification.credential_public_key),
            "credential_id": credential_id_b64,
            "sign_count": int(verification.sign_count),
            "transports": json.dumps(
                {
                    "transports": credential_payload.get("response", {}).get("transports", []),
                    "rp_id": self.rp_id,
                    "origin": self.base_auth_url,
                }
            ),
            "credential_type": credential_payload.get("type", "public-key"),
            "trusted": True,
            "last_used": _iso(_utcnow()),
        }
        supabase.table("biometric_devices").insert(row).execute()
        supabase.table("biometric_sessions").update({"status": "APPROVED"}).eq("id", session.get("id")).execute()
        pending["used"] = True
        self.pending_challenges[session_token] = pending
        log_bio_event(
            {
                "event": "WEBAUTHN_REGISTER_VERIFY",
                "email": session.get("email"),
                "status": "SUCCESS",
                "credential_id": credential_id_b64,
            }
        )
        logger.info("Passkey registration stored for email=%s", session.get("email"))
        return True, "APPROVED"

    def webauthn_auth_start(self, session_token: str) -> Dict[str, Any]:
        if not WEBAUTHN_AVAILABLE:
            raise RuntimeError("Biometric feature unavailable: webauthn package missing.")
        session = self.get_session_by_token(session_token)
        if not session:
            raise ValueError("SESSION_NOT_FOUND")
        if self._mark_expired_if_needed(session):
            raise ValueError("SESSION_EXPIRED")
        if not self.base_auth_url or not self.rp_id:
            raise ValueError("ORIGIN_NOT_READY")

        email = session.get("email")
        allow_credentials = self._registered_credentials(email)
        if not allow_credentials:
            raise ValueError("NO_TRUSTED_DEVICE")
        if self._origin_mismatch_for_email(email):
            log_bio_event(
                {
                    "event": "WEBAUTHN_AUTH_START",
                    "email": email,
                    "status": "FAILED",
                    "error": "ORIGIN_MISMATCH",
                }
            )
            raise ValueError("ORIGIN_CHANGED_REQUIRES_REREGISTRATION")

        options = generate_authentication_options(
            rp_id=self.rp_id,
            timeout=60000,
            user_verification=UserVerificationRequirement.REQUIRED,
            allow_credentials=allow_credentials,
        )
        payload = json.loads(options_to_json(options))
        self.pending_challenges[session_token] = {
            **self.pending_challenges.get(session_token, {}),
            "challenge": payload["challenge"],
            "used": False,
            "flow": "auth",
            "origin": self.base_auth_url,
            "rp_id": self.rp_id,
            "created_at": time.time(),
        }
        logger.info("WebAuthn authentication challenge created for %s", email)
        log_bio_event(
            {
                "event": "WEBAUTHN_AUTH_START",
                "email": email,
                "rp_id": self.rp_id,
                "challenge_b64": payload["challenge"],
            }
        )
        return payload

    def webauthn_auth_finish(self, session_token: str, credential_payload: Dict[str, Any]) -> tuple[bool, str]:
        if not WEBAUTHN_AVAILABLE:
            raise RuntimeError("Biometric feature unavailable: webauthn package missing.")
        session = self.get_session_by_token(session_token)
        if not session:
            return False, "SESSION_NOT_FOUND"
        if self._mark_expired_if_needed(session):
            return False, "SESSION_EXPIRED"

        pending = self.pending_challenges.get(session_token) or {}
        if pending.get("used"):
            logger.warning("Replay attempt blocked for auth session=%s", session_token[:8])
            return False, "REPLAY_BLOCKED"

        challenge = pending.get("challenge")
        if not challenge:
            logger.warning("Authentication failed for session=%s: challenge missing from state.", session_token[:8])
            return False, "CHALLENGE_MISSING"

        cred_id = credential_payload.get("id") or ""
        email = session.get("email")
        logger.info("Verifying authentication for session=%s | email=%s | cred_id=%s", session_token[:8], email, cred_id)

        device_result = (
            supabase.table("biometric_devices")
            .select("*")
            .eq("email", email)
            .eq("credential_id", cred_id)
            .eq("trusted", True)
            .limit(1)
            .execute()
        )
        rows = device_result.data or []
        if not rows:
            logger.warning("Credential ID %s not found for user %s", cred_id, email)
            return False, "CREDENTIAL_NOT_FOUND"
        device = rows[0]
        logger.info("Found matching trusted device record for credential_id: %s", cred_id)

        public_key = device.get("public_key")
        if not public_key:
            logger.error("Device record for cred_id=%s is missing public_key", cred_id)
            return False, "PUBLIC_KEY_MISSING"

        expected_rp_id = pending.get("rp_id") or self.rp_id
        expected_origin = pending.get("origin") or self.base_auth_url
        current_sign_count = int(device.get("sign_count") or 0)
        logger.debug(
            "Auth verification details | rp_id=%s | origin=%s | sign_count=%d",
            expected_rp_id,
            expected_origin,
            current_sign_count,
        )
        log_bio_event(
            {
                "event": "WEBAUTHN_AUTH_VERIFY",
                "email": email,
                "rp_id": expected_rp_id,
                "origin": expected_origin,
                "credential_id": cred_id,
                "expected_challenge_b64": challenge,
            }
        )
        # Add detailed payload logging for debugging
        try:
            client_data_json_b64 = credential_payload.get("response", {}).get("clientDataJSON")
            if client_data_json_b64:
                client_data_json = _b64_to_bytes(client_data_json_b64).decode("utf-8")
                client_challenge = json.loads(client_data_json).get("challenge")
                log_bio_event(
                    {
                        "event": "WEBAUTHN_CLIENT_CHALLENGE",
                        "client_challenge_b64": client_challenge,
                    }
                )
        except Exception:
            pass

        try:
            verification = verify_authentication_response(credential=credential_payload, expected_challenge=_b64_to_bytes(challenge), expected_rp_id=expected_rp_id, expected_origin=expected_origin, credential_public_key=_b64_to_bytes(str(public_key)), credential_current_sign_count=current_sign_count, require_user_verification=True)
        except Exception as error:
            logger.exception("WebAuthn auth verification failed for session=%s: %s", session_token[:8], error)
            log_bio_event(
                {
                    "event": "WEBAUTHN_AUTH_VERIFY",
                    "email": email,
                    "status": "FAILED",
                    "error_type": str(error.__class__.__name__),
                    "error_details": str(error),
                }
            )
            return False, "VERIFY_FAILED"

        new_sign_count = int(verification.new_sign_count)
        if new_sign_count <= current_sign_count and current_sign_count != 0:
            logger.warning(
                "Potential cloned authenticator detected for credential=%s. Stored sign_count: %d, received: %d",
                cred_id,
                current_sign_count,
                new_sign_count,
            )
            return False, "SIGN_COUNT_INVALID"

        supabase.table("biometric_devices").update({"sign_count": new_sign_count, "last_used": _iso(_utcnow())}).eq("id", device.get("id")).execute()
        supabase.table("biometric_sessions").update({"status": "APPROVED"}).eq("id", session.get("id")).execute()
        pending["used"] = True
        self.pending_challenges[session_token] = pending
        log_bio_event(
            {
                "event": "WEBAUTHN_AUTH_VERIFY",
                "email": email,
                "status": "SUCCESS",
                "credential_id": cred_id,
                "new_sign_count": new_sign_count,
            }
        )
        logger.info("Passkey authentication verified for email=%s", session.get("email"))
        return True, "APPROVED"

    def consume_success(self, email: str, session_token: str) -> bool:
        if not WEBAUTHN_AVAILABLE:
            return False
        row = self.get_session_by_token(session_token) or {}
        if not row:
            return False
        if self._mark_expired_if_needed(row):
            return False

        status = (row.get("status") or "").upper()
        if status != "APPROVED":
            return False

        (
            supabase.table("biometric_sessions")
            .update({"status": "COMPLETED"})
            .eq("id", row.get("id"))
            .execute()
        )

        runtime_state.update(
            authenticated=True,
            current_user=email,
            current_email=email,
            auth_method="biometric",
            last_auth_time=_iso(_utcnow()),
            failed_biometric_attempts=0,
        )
        runtime_state.set_nested("biometric_state", {"pairing_state": "completed"})
        event_bus.publish(
            {
                "event_type": "AUTH_SUCCESS",
                "email": email,
                "auth_method": "biometric",
                "severity": "LOW",
                "timestamp": time.time(),
            }
        )
        log_bio_event(
            {
                "event": "BIOMETRIC_LOGIN_SUCCESS",
                "email": email,
                "session_token": session_token[:8],
            }
        )
        return True

    def record_failure(self, email: str, reason: str) -> None:
        snap = runtime_state.snapshot()
        attempts = int(snap.get("failed_biometric_attempts", 0)) + 1
        runtime_state.update(authenticated=False, failed_biometric_attempts=attempts)
        event_bus.publish(
            {
                "event_type": "AUTH_FAIL",
                "email": email,
                "reason": reason,
                "severity": "MEDIUM",
                "timestamp": time.time(),
            }
        )
        log_bio_event(
            {
                "event": "BIOMETRIC_LOGIN_FAILED",
                "email": email,
                "reason": reason,
                "attempts": attempts,
            }
        )
        if attempts >= self.max_failed_attempts:
            event_bus.publish(
                {
                    "event_type": "AUTH_BRUTE_FORCE",
                    "email": email,
                    "reason": "BIOMETRIC_MAX_ATTEMPTS",
                    "severity": "CRITICAL",
                    "timestamp": time.time(),
                }
            )


biometric_manager = BiometricManager()
