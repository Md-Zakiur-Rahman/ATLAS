import smtplib
import socket
import secrets
import os
import hashlib # Keep hashlib as it's used later
from datetime import datetime, timedelta
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.image import MIMEImage
from config.logging_config import get_logger
from core.runtime_state import runtime_state
from database.client import supabase
from core.session import session

logger = get_logger("emails")


class EmailSender:

    def get_user_email(self) -> str:
        email = session.get_email()
        if email is None:
            email = runtime_state.snapshot().get("current_email")

        if email is None:
            logger.warning(
                "No active session email; email not sent."
            )
            return None

        return email

    def _send_email(
        self,
        subject: str,
        body: str,
        screenshot_path: str = None
    ) -> None:

        if runtime_state.snapshot().get("replay_active"):
            return

        smtp_host = os.getenv("SMTP_HOST", "smtp.resend.com")
        smtp_port = os.getenv("SMTP_PORT", "465")
        smtp_user = os.getenv("SMTP_USER", "resend")
        smtp_password = os.getenv("RESEND_API_KEY")
        smtp_from = os.getenv("SMTP_FROM")

        if not all([smtp_host, smtp_port, smtp_user, smtp_password, smtp_from]):
            logger.debug("SMTP configuration missing; email skipped.")
            return

        recipient = self.get_user_email()

        if recipient is None:
            return

        try:
            message = MIMEMultipart()
            message["From"] = smtp_from
            message["To"] = recipient
            message["Subject"] = subject
            message.attach(
                MIMEText(
                    body,
                    "plain"
                )
            )

            if (
                screenshot_path
                and os.path.exists(screenshot_path)
            ):
                with open(screenshot_path, "rb") as image_file:
                    image = MIMEImage(image_file.read())
                    image.add_header(
                        "Content-Disposition",
                        "attachment",
                        filename=os.path.basename(screenshot_path)
                    )
                    message.attach(image)

            with smtplib.SMTP_SSL(smtp_host, int(smtp_port)) as smtp:
                smtp.login(
                    smtp_user,
                    smtp_password
                )
                smtp.sendmail(
                    smtp_from,
                    recipient,
                    message.as_string()
                )

            logger.info(
                "Email sent to %s: %s",
                recipient,
                subject
            )

        except Exception as error:
            logger.warning(
                "Email send failed: %s",
                error
            )

    def send_otp(self, otp_code: str):
        email = self.get_user_email()

        if email is None:
            return

        otp_hash = hashlib.sha256(otp_code.encode()).hexdigest()

        supabase.table("otp_sessions").insert({
            "otp_code": otp_hash,
            "email": email,
            "expires_at": (datetime.utcnow() + timedelta(seconds=60)).isoformat(),
            "verified": False,
            "failed_attempts": 0,
        }).execute()

        body = (
            f"Your ATLAS login code: {otp_code}\n"
            "This code expires in 60 seconds.\n"
            "Do not share this code with anyone."
        )

        self._send_email(
            "ATLAS Login Code",
            body
        )

    def verify_otp(self, otp_code: str) -> bool:
        otp_hash = hashlib.sha256(otp_code.encode()).hexdigest()

        result = (
            supabase.table("otp_sessions")
            .select("*")
            .eq("otp_code", otp_hash)
            .eq("verified", False)
            .execute()
        )

        if not result.data:
            return False

        row = result.data[0]
        expires_at = row.get("expires_at")

        if not expires_at:
            return False

        try:
            expires_at = datetime.fromisoformat(
                str(expires_at).replace("Z", "")
            )
        except ValueError:
            return False

        if expires_at < datetime.utcnow():
            return False

        (
            supabase.table("otp_sessions")
            .update({"verified": True})
            .eq("otp_code", otp_hash)
            .execute()
        )

        return True

    def send_critical_alert(
        self,
        event: dict,
        screenshot_path: str = None
    ):
        email = self.get_user_email()

        if email is None:
            return

        token = secrets.token_urlsafe(32)

        token_hash = hashlib.sha256(token.encode()).hexdigest()

        supabase.table("vault_lock_tokens").insert({
            "token_hash": token_hash, # This is not an event_type, it's a column name. No change needed.
            "email": email,
            "expires_at": (datetime.utcnow() + timedelta(minutes=5)).isoformat(),
            "used": False,
            "severity": event.get("severity", "CRITICAL"),
            "threat_type": event.get("type", "UNKNOWN"),
        }).execute()

        host = socket.gethostname()

        try:
            host_ip = socket.gethostbyname(host)
        except Exception:
            host_ip = "127.0.0.1"

        bio_state = runtime_state.snapshot().get("biometric_state", {})
        base_url = bio_state.get("base_auth_url")

        if not base_url:
            base_url = f"http://{host_ip}:80"

        lock_url = f"{base_url}/remote-lock?token={token}"

        body_lines = [
            f"Threat type: {event.get('event_type')}",
            f"Machine: {host}",
            f"Timestamp: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}",
        ]

        if event.get("pid"):
            body_lines.append(
                f"Process PID: {event.get('pid')}"
            )

        if event.get("ransomware_detected") is not None:
            body_lines.append(
                f"Ransomware detected: {event.get('ransomware_detected')}"
            )

        if event.get("attacker_ip"):
            body_lines.append(
                f"Attacker IP: {event.get('attacker_ip')}"
            )

        body_lines.append(
            f"One-click vault lock: {lock_url}"
        )

        self._send_email(
            "ATLAS CRITICAL THREAT DETECTED",
            "\n".join(body_lines),
            screenshot_path
        )

    def send_high_alert(self, event: dict):
        email = self.get_user_email()

        if email is None:
            return

        body_lines = [
            f"Threat type: {event.get('event_type')}",
            f"Timestamp: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}",
            "Action taken: auto-handled",
        ]

        if event.get("process_name"):
            body_lines.append(
                f"Process name: {event.get('process_name')}"
            )

        if event.get("pid"):
            body_lines.append(
                f"Process PID: {event.get('pid')}"
            )

        if event.get("attacker_ip"):
            body_lines.append(
                f"Attacker IP: {event.get('attacker_ip')}"
            )

        if event.get("city"):
            body_lines.append(
                f"City: {event.get('city')}"
            )

        if event.get("port"):
            body_lines.append(
                f"Port: {event.get('port')}"
            )

        self._send_email(
            "ATLAS HIGH Threat Detected",
            "\n".join(body_lines)
        )

    def send_medium_alert(self, event: dict):
        email = self.get_user_email()

        if email is None:
            return

        body_lines = [
            f"ML anomaly score: {event.get('score')}",
            f"Timestamp: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}",
            "Recommendation: review the ATLAS dashboard.",
        ]

        if event.get("top_contributing_features"):
            body_lines.append(
                f"Top contributing features: {event.get('top_contributing_features')}"
            )

        self._send_email(
            "ATLAS MEDIUM Threat - Anomaly Detected",
            "\n".join(body_lines)
        )

    def send_block_confirm(
        self,
        files_restored: int,
        attacker_ip: str = None
    ):
        email = self.get_user_email()

        if email is None:
            return

        body = (
            "Attack contained successfully.\n"
            f"Files restored: {files_restored}\n"
            f"Attacker IP blacklisted: {attacker_ip or 'N/A'}\n"
            "Your system is secured."
        )

        self._send_email(
            "ATLAS Attack Blocked",
            body
        )


email_sender = EmailSender()
