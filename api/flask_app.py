from flask import Flask, request, jsonify, Response
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from core.crypto_service import activate_vault_lock
from core.runtime_state import runtime_state
from database.client import supabase
from auth.session_manager import session_manager
from auth.otp_manager import otp_manager
from monitor.event_bus import event_bus
from monitor.network_monitor import network_monitor
import time
import os
import hashlib
from datetime import datetime
from config.logging_config import get_logger


app = Flask(__name__)
# Load secret key from environment for session security. Fallback for development.
app.secret_key = os.getenv("FLASK_SECRET_KEY") or "a-temporary-insecure-secret-key"


logger = get_logger("api")

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["10 per minute"],
    storage_uri="memory://"
)


@app.before_request
def log_biometric_request():
    if request.path.startswith("/biometric"):
        logger.info(
            "Incoming biometric request path=%s method=%s remote=%s",
            request.path,
            request.method,
            request.remote_addr,
        )


@app.before_request
def check_blacklist():
    ip = request.remote_addr
    if ip in network_monitor.ip_blacklist:
        logger.warning("Blocked request from blacklisted IP: %s", ip)
        return jsonify({
            "error": "Access denied",
            "reason": "IP blacklisted"
        }), 403


@app.route("/auth-verify", methods=["POST"])
@limiter.limit("10 per minute")
def auth_verify():
    payload = request.get_json(silent=True) or {}
    email = payload.get("email")
    password = payload.get("password")

    if not email or not password:
        return jsonify({"error": "email and password are required"}), 400

    try:
        result = supabase.table("auth").select("*").eq("email", email).execute()
        rows = result.data or []

        if not rows:
            # Publish AUTH_FAIL for user not found
            event_bus.publish({
                "type": "AUTH_FAIL",
                "email": email,
                "reason": "USER_NOT_FOUND",
                "severity": "MEDIUM",
                "timestamp": time.time(),
            })
            return jsonify({"error": "user not found"}), 404

        user = rows[0]
        stored_password_hash = user.get("password_hash")
        provided_password_hash = hashlib.sha256(password.encode("utf-8")).hexdigest()
        stored_password = user.get("password")
        is_valid_password = False
        if stored_password_hash:
            is_valid_password = stored_password_hash == provided_password_hash
        elif stored_password:
            is_valid_password = stored_password == password

        if not is_valid_password:
            otp_manager.increment_failed_attempts(email)
            event_bus.publish({"type": "AUTH_FAIL", "email": email, "reason": "INVALID_PASSWORD", "severity": "MEDIUM", "timestamp": time.time()})
            return jsonify({"error": "invalid credentials"}), 401

        # Password-only is not enough; MFA step is mandatory.
        return jsonify({"status": "password_verified", "mfa_required": True, "email": email}), 200

    except Exception as error:
        logger.exception("/auth-verify failed: %s", error)
        runtime_state.update(api_status="error")
        return jsonify({"error": "internal server error"}), 500


@app.route("/auth-otp", methods=["POST"])
@limiter.limit("10 per minute")
def auth_otp():
    payload = request.get_json(silent=True) or {}
    email = payload.get("email")

    if not email:
        return jsonify({"error": "email is required"}), 400

    try:
        success = otp_manager.send_email_otp(email)
        if success:
            return jsonify({"status": "otp sent", "email": email}), 200
        # Publish AUTH_FAIL if OTP sending fails
        event_bus.publish({
            "type": "AUTH_FAIL",
            "email": email,
            "reason": "OTP_SEND_FAILED",
            "severity": "MEDIUM",
            "timestamp": time.time(),
        })
        return jsonify({"error": "failed to send otp"}), 500
    except Exception as error:
        logger.exception("/auth-otp failed: %s", error)
        runtime_state.update(api_status="error")
        return jsonify({"error": "internal server error"}), 500


@app.route("/remote-lock", methods=["GET"])
def remote_lock():
    token = request.args.get("token")
    if not token:
        return jsonify({"error": "token is required"}), 400

    token_hash = hashlib.sha256(token.encode()).hexdigest()

    try:
        result = (
            supabase
            .table("vault_lock_tokens")
            .select("*")
            .eq("token_hash", token_hash)
            .eq("used", False)
            .execute()
        )
        rows = result.data or []

        if not rows:
            return jsonify({"error": "invalid or used token"}), 403

        session = rows[0]

        expires_at = session.get("expires_at")
        if expires_at:
            expires_dt = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
            if datetime.now(expires_dt.tzinfo) > expires_dt:
                return jsonify({"error": "token expired"}), 403

        email = session.get("email")
        if not email:
            return jsonify({"error": "token has no email binding"}), 403

        (
            supabase
            .table("otp_sessions")
            .update({"used": True})
            .eq("id", session.get("id"))
            .execute()
        )

        event_bus.publish({
            "type": "VAULT_LOCKED",
            "email": email,
            "severity": "CRITICAL",
            "timestamp": time.time(),
        })
        runtime_state.update(vault_locked=True)
        activate_vault_lock("Remote lock endpoint trigger")

        supabase.table("auth").update({"vault_locked": True}).eq("email", email).execute()

        return jsonify({"status": "vault locked"}), 200

    except Exception as error:
        logger.exception("/remote-lock failed: %s", error)
        runtime_state.update(api_status="error")
        return jsonify({"error": "internal server error"}), 500


@app.route("/health", methods=["GET"])
def health():
    runtime_state.update(api_status="online")
    return jsonify({"status": "ATLAS running"}), 200


# --- WebAuthn / Biometric Routes ---
try:
    from auth.biometric_manager import WEBAUTHN_AVAILABLE, biometric_manager, log_bio_event

    if not WEBAUTHN_AVAILABLE:
        raise ImportError("webauthn package not available, biometric routes disabled.")

    @app.route("/biometric/pair/<qr_token>", methods=["GET"])
    def biometric_pair_page(qr_token):
        session = biometric_manager.get_session_by_qr(qr_token)
        if session:
            log_bio_event(
                {
                    "event": "QR_SCANNED",
                    "email": session.get("email"),
                    "qr_token": qr_token,
                    "flow": session.get("status"),
                }
            )
            try:
                supabase.table("biometric_sessions").update({"status": "SCANNED"}).eq("id", session.get("id")).execute()
            except Exception:
                pass
        if not session:
            return Response("<h3>Session not found</h3>", status=404, mimetype="text/html")

        status = (session.get("status") or "").upper()
        if status in {"COMPLETED", "DENIED", "EXPIRED"}:
            return Response(f"<h3>Session closed: {status}</h3>", status=200, mimetype="text/html")

        if biometric_manager._mark_expired_if_needed(session):  # noqa: SLF001
            return Response("<h3>Session expired</h3>", status=200, mimetype="text/html")

        email = session.get("email", "unknown")
        session_token = session.get("session_token")
        tunnel_origin = biometric_manager.base_auth_url or ""
        title = "Passkey Registration" if status == "PENDING_REGISTRATION" else "Passkey Authentication"
        action_hint = "Register this device passkey for ATLAS." if status == "PENDING_REGISTRATION" else "Authenticate with FaceID / Fingerprint / Device PIN."
        html = f"""
    <html>
    <head>
    <meta name="viewport" content="width=device-width,initial-scale=1"/>
    <style>
    body{{font-family: 'JetBrains Mono', monospace; background:#e8e0cf; color:#111; margin:0;}}
    .shell{{max-width:560px; margin:18px auto; border:4px solid #111; background:#f2e9d8; padding:14px;}}
    .blk{{border:2px solid #111; background:#e2d8c3; padding:8px; margin-top:8px;}}
    .btn{{width:100%; border:3px solid #111; background:#88aeb0; color:#111; padding:10px; font-weight:700;}}
    .muted{{color:#444; font-size:12px;}}
    </style>
    </head>
    <body>
      <div class="shell">
        <h2>{title}</h2>
        <div class="blk"><b>Email:</b> {email}</div>
        <div class="blk"><b>Secure Tunnel:</b> {tunnel_origin}</div>
        <div class="blk" id="state">{action_hint}</div>
        <div class="blk muted">Preparing secure enclave...</div>
        <button class="btn" onclick="runFlow()">Continue</button>
        <div class="blk muted" id="log">Waiting for biometric verification...</div>
      </div>
    <script>
    function b64ToBytes(b64url){{
      const pad = '='.repeat((4 - b64url.length % 4) % 4);
      const b64 = (b64url + pad).replace(/-/g,'+').replace(/_/g,'/');
      const raw = atob(b64);
      return Uint8Array.from([...raw].map(c => c.charCodeAt(0)));
    }}
    function bytesToB64url(bytes){{
      const bin = String.fromCharCode(...new Uint8Array(bytes));
      return btoa(bin).replace(/\\+/g,'-').replace(/\\//g,'_').replace(/=+$/,'');
    }}
    function normalizeCreationOptions(opts){{
      opts.challenge = b64ToBytes(opts.challenge);
      opts.user.id = b64ToBytes(opts.user.id);
      if (opts.excludeCredentials){{
        opts.excludeCredentials = opts.excludeCredentials.map(c => ({{...c, id:b64ToBytes(c.id)}}));
      }}
      return opts;
    }}
    function normalizeRequestOptions(opts){{
      opts.challenge = b64ToBytes(opts.challenge);
      if (opts.allowCredentials){{
        opts.allowCredentials = opts.allowCredentials.map(c => ({{...c, id:b64ToBytes(c.id)}}));
      }}
      return opts;
    }}
    function credentialToJSON(cred){{
      if(!cred) return null;
      return {{
        id: cred.id,
        rawId: bytesToB64url(cred.rawId),
        type: cred.type,
        response: {{
          attestationObject: cred.response.attestationObject ? bytesToB64url(cred.response.attestationObject) : null,
          clientDataJSON: bytesToB64url(cred.response.clientDataJSON),
          authenticatorData: cred.response.authenticatorData ? bytesToB64url(cred.response.authenticatorData) : null,
          signature: cred.response.signature ? bytesToB64url(cred.response.signature) : null,
          userHandle: cred.response.userHandle ? bytesToB64url(cred.response.userHandle) : null,
          transports: cred.response.getTransports ? cred.response.getTransports() : [],
        }},
        clientExtensionResults: cred.getClientExtensionResults ? cred.getClientExtensionResults() : {{}},
      }};
    }}
    async function runFlow(){{
      const state = document.getElementById('state');
      const log = document.getElementById('log');
      try {{
        let startUrl = '/webauthn/auth/start';
        let finishUrl = '/webauthn/auth/finish';
        let flow = '{status}';
        if (flow === 'PENDING_REGISTRATION'){{
          startUrl = '/webauthn/register/start';
          finishUrl = '/webauthn/register/finish';
          state.textContent = 'Registering passkey...';
        }} else {{
          state.textContent = 'Authenticating with passkey...';
        }}
        const startResp = await fetch(startUrl, {{
          method:'POST', headers:{{'Content-Type':'application/json'}},
          body: JSON.stringify({{session_token:'{session_token}'}})
        }});
        const startData = await startResp.json();
        if(!startResp.ok) throw new Error(startData.error || 'start failed');
        log.textContent = 'Waiting for FaceID/fingerprint...';
        let credential;
        if (flow === 'PENDING_REGISTRATION'){{
          credential = await navigator.credentials.create({{publicKey: normalizeCreationOptions(startData.options)}});
        }} else {{
          credential = await navigator.credentials.get({{publicKey: normalizeRequestOptions(startData.options)}});
        }}
        log.textContent = 'Verifying signed challenge...';
        const payload = credentialToJSON(credential);
        const finishResp = await fetch(finishUrl, {{
          method:'POST', headers:{{'Content-Type':'application/json'}},
          body: JSON.stringify({{session_token:'{session_token}', credential: payload, device_name: 'Mobile Passkey'}})
        }});
        const finishData = await finishResp.json();
        if(!finishResp.ok) throw new Error(finishData.error || 'finish failed');
        state.textContent = 'Secure login approved.';
        log.textContent = 'Credential verification complete.';
      }} catch (e) {{
        state.textContent = 'Biometric verification failed.';
        log.textContent = String(e);
      }}
    }}
    </script>
    </body>
    </html>
        """
        return Response(html, status=200, mimetype="text/html")


    @app.route("/webauthn/register/start", methods=["POST"])
    def webauthn_register_start():
        payload = request.get_json(silent=True) or {}
        session_token = payload.get("session_token")
        if not session_token:
            return jsonify({"error": "session_token required"}), 400
        try:
            options = biometric_manager.webauthn_register_start(session_token)
            return jsonify({"options": options}), 200
        except ValueError as error:
            return jsonify({"error": str(error)}), 400
        except Exception as error:
            logger.exception("register/start failed: %s", error)
            return jsonify({"error": "internal server error"}), 500


    @app.route("/webauthn/register/finish", methods=["POST"])
    def webauthn_register_finish():
        payload = request.get_json(silent=True) or {}
        session_token = payload.get("session_token")
        credential = payload.get("credential")
        device_name = payload.get("device_name") or "Mobile Passkey"
        if not session_token or not credential:
            return jsonify({"error": "session_token and credential required"}), 400
        ok, reason = biometric_manager.webauthn_register_finish(session_token, credential, device_name)
        return jsonify({"status": reason}), (200 if ok else 400)


    @app.route("/webauthn/auth/start", methods=["POST"])
    def webauthn_auth_start():
        payload = request.get_json(silent=True) or {}
        session_token = payload.get("session_token")
        if not session_token:
            return jsonify({"error": "session_token required"}), 400
        try:
            options = biometric_manager.webauthn_auth_start(session_token)
            return jsonify({"options": options}), 200
        except ValueError as error:
            return jsonify({"error": str(error)}), 400
        except Exception as error:
            logger.exception("auth/start failed: %s", error)
            return jsonify({"error": "internal server error"}), 500


    @app.route("/webauthn/auth/finish", methods=["POST"])
    def webauthn_auth_finish():
        payload = request.get_json(silent=True) or {}
        session_token = payload.get("session_token")
        credential = payload.get("credential")
        if not session_token or not credential:
            return jsonify({"error": "session_token and credential required"}), 400
        ok, reason = biometric_manager.webauthn_auth_finish(session_token, credential)
        return jsonify({"status": reason}), (200 if ok else 400)

    logger.info("Biometric/WebAuthn API routes enabled.")

except (ImportError, RuntimeError) as e:
    logger.warning("Biometric/WebAuthn API routes disabled: %s", e)


@app.errorhandler(429)
def rate_limit_exceeded(e):
    ip = request.remote_addr
    logger.warning("Rate limit exceeded from IP: %s", ip)
    event_bus.publish({
        "type": "RATE_LIMIT_EXCEEDED",
        "ip": ip,
        "severity": "MEDIUM",
        "timestamp": time.time()
    })
    return jsonify({
        "error": "Too many requests",
        "retry_after": "60 seconds"
    }), 429


from database.db_manager import db_manager
db_manager.verify_on_startup()
runtime_state.update(supabase_status="online")

if __name__ == "__main__":
    logger.info("Starting Flask API on bind address 0.0.0.0:80")
    app.run(host="0.0.0.0", port=80, debug=False)
