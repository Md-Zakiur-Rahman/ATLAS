from flask import Flask, request, jsonify
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from database.client import supabase
from auth.session_manager import session_manager
from auth.otp_manager import otp_manager
from monitor.event_bus import event_bus
from monitor.network_monitor import network_monitor
import logging
import time
import os
from datetime import datetime


app = Flask(__name__)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
)
logger = logging.getLogger("ATLAS-FlaskAPI")

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["10 per minute"],
    storage_uri="memory://"
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
            return jsonify({"error": "user not found"}), 404

        user = rows[0]
        stored_password = user.get("password")

        if stored_password != password:
            otp_manager.increment_failed_attempts(email)
            event_bus.publish({
                "type": "AUTH_FAIL",
                "email": email,
                "severity": "MEDIUM",
                "timestamp": time.time(),
            })
            return jsonify({"error": "invalid credentials"}), 401

        session_manager.create_session(email)
        return jsonify({"status": "success", "email": email}), 200

    except Exception as error:
        logger.exception("/auth-verify failed: %s", error)
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
        return jsonify({"error": "failed to send otp"}), 500
    except Exception as error:
        logger.exception("/auth-otp failed: %s", error)
        return jsonify({"error": "internal server error"}), 500


@app.route("/remote-lock", methods=["GET"])
def remote_lock():
    token = request.args.get("token")
    if not token:
        return jsonify({"error": "token is required"}), 400

    try:
        result = (
            supabase
            .table("otp_sessions")
            .select("*")
            .eq("code", token)
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

        supabase.table("auth").update({"vault_locked": True}).eq("email", email).execute()

        return jsonify({"status": "vault locked"}), 200

    except Exception as error:
        logger.exception("/remote-lock failed: %s", error)
        return jsonify({"error": "internal server error"}), 500


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ATLAS running"}), 200


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

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)