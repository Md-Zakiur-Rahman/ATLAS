"""
ATLAS Notification Manager

Handles:
- Event bus subscription
- Notification table inserts
- SMTP email delivery for security alerts
"""

import logging
import os
import smtplib
from datetime import datetime
from email.mime.text import MIMEText

from database.client import (
    supabase
)

from monitor.event_bus import (
    event_bus
)


logging.basicConfig(
    level=logging.INFO,
    format=(
        "%(asctime)s | "
        "%(levelname)s | "
        "%(message)s"
    )
)

logger = logging.getLogger(
    "ATLAS-NotificationManager"
)


class NotificationManager:

    def __init__(self):

        self.templates = {
            "AUTH_BRUTE_FORCE": {
                "subject": "🚨 ATLAS — Brute Force Attack Detected",
                "body": (
                    "Multiple failed login attempts were detected on your account. "
                    "Your vault has been locked automatically as a precaution. "
                    "If this was not you, contact support immediately."
                ),
            },
            "AUTH_FAIL": {
                "subject": "⚠️ ATLAS — Suspicious Login Attempt",
                "body": (
                    "A failed login attempt was recorded on your account. "
                    "If this was not you, please secure your account immediately."
                ),
            },
            "AUTH_SUCCESS": {
                "subject": "ATLAS Login Success",
                "body": (
                    "A successful authentication was recorded.\n"
                    "Account: {email}"
                ),
            },
            "OTP_SENT": {
                "subject": "ATLAS OTP Sent",
                "body": (
                    "A one-time password was issued.\n"
                    "Account: {email}"
                ),
            },
        }

        event_bus.subscribe(
            self.process_event
        )

    def process_event(
        self,
        event: dict
    ) -> None:

        event_type = event.get("type")

        if event_type not in (
            "AUTH_BRUTE_FORCE",
            "AUTH_FAIL",
            "AUTH_SUCCESS",
            "OTP_SENT",
        ):
            return

        email = event.get("email")
        reason = event.get("reason", "N/A")

        if not email:
            logger.warning(
                "Notification skipped; missing email for event: %s",
                event_type
            )
            return

        template = self.templates.get(event_type, {})
        subject = template.get("subject", f"ATLAS Notification - {event_type}")
        body = template.get("body", "ATLAS event received.").format(
            email=email,
            reason=reason,
        )

        self._log_notification(
            email=email,
            event_type=event_type,
            subject=subject,
            body=body,
            reason=reason,
        )

        if event_type in ("AUTH_SUCCESS", "OTP_SENT"):
            logger.info(
                "Notification logged only (no email): %s for %s",
                event_type,
                email
            )
            return

        self._send_email(
            recipient=email,
            subject=subject,
            body=body,
        )

    def _log_notification(
        self,
        email: str,
        event_type: str,
        subject: str,
        body: str,
        reason: str
    ) -> None:

        try:

            supabase.table("notifications").insert(
                {
                    "email": email,
                    "type": event_type,
                    "subject": subject,
                    "body": body,
                    "reason": reason,
                    "sent_at": datetime.utcnow().isoformat(),
                    "acknowledged": False,
                }
            ).execute()

            logger.info(
                "Notification logged: %s for %s",
                event_type,
                email
            )

        except Exception as error:

            logger.exception(
                "Notification Log Error: %s",
                error
            )

    def _send_email(
        self,
        recipient: str,
        subject: str,
        body: str
    ) -> None:

        smtp_host = os.getenv("SMTP_HOST", "smtp.resend.com")
        smtp_port = os.getenv("SMTP_PORT", "465")
        smtp_user = os.getenv("SMTP_USER", "resend")
        smtp_password = os.getenv("RESEND_API_KEY")
        smtp_from = os.getenv("SMTP_FROM")

        if not all([smtp_host, smtp_port, smtp_user, smtp_password, smtp_from]):
            logger.debug("SMTP configuration missing; email skipped.")
            return

        try:

            message = MIMEText(
                body,
                "plain"
            )
            message["Subject"] = subject
            message["From"] = smtp_from
            message["To"] = recipient

            with smtplib.SMTP_SSL(
                smtp_host,
                int(smtp_port)
            ) as smtp:
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
                "Notification email sent to %s: %s",
                recipient,
                subject
            )

        except Exception as error:

            logger.warning(
                "Notification Email Send Failed: %s",
                error
            )


notification_manager = NotificationManager()
