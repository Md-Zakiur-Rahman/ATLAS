"""
ATLAS Supabase Email OTP Manager

Handles:
- Email OTP requests
- OTP verification
- AUTH_SUCCESS events
- AUTH_FAIL events
- Failed attempt tracking
"""
import time
from typing import Optional

from config.logging_config import get_logger
from core.runtime_state import runtime_state
from core.session import session
from core.crypto_service import activate_vault_lock
from database.client import (
    supabase
)

from monitor.event_bus import (
    event_bus
)
logger = get_logger("auth")


class OTPManager:

    def __init__(self):

        self.max_failed_attempts = 3

    # =====================================================
    # Send Email OTP
    # =====================================================

    def send_email_otp(
        self,
        email: str
    ) -> bool:

        try:

            response = (
    supabase.auth.sign_in_with_otp(
        {
            "email": email,

            "options": {
                "should_create_user": True
            }
        }
    )
)

            logger.info(
                "OTP sent to %s",
                email
            )

            event_bus.publish(
                {
                    "event_type": "OTP_SENT",
                    "email": email,
                    "severity": "LOW",
                    "timestamp": time.time(),
                    }
            )

            return True

        except Exception as error:

            logger.exception(
                "OTP Send Error: %s",
                error
            )

            event_bus.publish(
                {
                    "event_type": "AUTH_FAIL",

                    "email": email,

                    "reason": (
                        "OTP_SEND_FAILED"
                    ),
                    "severity": "MEDIUM",
                    "timestamp": time.time(),
                }
            )

            return False

    # =====================================================
    # Verify Email OTP
    # =====================================================

    def verify_email_otp(
        self,
        email: str,
        otp: str
    ) -> bool:

        try:

            response = (
                supabase.auth.verify_otp(
                    {
                        "email": email,

                        "token": otp,

                        "type": "magiclink"
                    }
                )
            )

            user = (
                response.user
            )

            if not user:

                self.increment_failed_attempts(
                    email
                )

                event_bus.publish(
                    {
                        "event_type": "AUTH_FAIL",

                        "email": email,

                        "reason": (
                            "INVALID_OTP"
                        ),
                        "severity": "MEDIUM",
                        "timestamp": time.time(),
                    }
                )

                logger.warning(
                    "OTP verification failed"
                )
                runtime_state.update(authenticated=False)

                return False

            self.reset_failed_attempts(
                email
            )

            self.update_last_login(
                email
            )

            event_bus.publish(
                {
                    "event_type": "AUTH_SUCCESS",
                    "email": email,
                    "auth_method": "otp",
                    "severity": "LOW",
                    "timestamp": time.time(),
                }
            )
            session.set_user(email)
            runtime_state.update(
                current_user=email,
                current_email=email,
                authenticated=True,
                auth_method="otp",
                failed_otp_attempts=0,
            )

            logger.info(
                "OTP verified for %s",
                email
            )

            return True

        except Exception as error:

            logger.exception(
                "OTP Verify Error: %s",
                error
            )

            self.increment_failed_attempts(
                email
            )

            event_bus.publish(
                {
                    "event_type": "AUTH_FAIL",

                    "email": email,

                    "reason": (
                        "OTP_EXCEPTION"
                    ),
                    "severity": "MEDIUM",
                    "timestamp": time.time(),
                }
            )

            return False

    # =====================================================
    # Failed Attempt Tracking
    # =====================================================

    def increment_failed_attempts(
        self,
        email: str
    ) -> None:

        try:

            response = (
                supabase.table("auth")
                .select(
                    "failed_attempts"
                )
                .eq(
                    "email",
                    email
                )
                .execute()
            )

            if not response.data:
                return

            current_attempts = (
                response.data[0]
                .get(
                    "failed_attempts",
                    0
                )
            )

            updated_attempts = (
                current_attempts + 1
            )

            supabase.table("auth").update(
                {
                    "failed_attempts":
                    updated_attempts
                }
            ).eq(
                "email",
                email
            ).execute()

            logger.warning(
                "Failed attempts for %s: %s",
                email,
                updated_attempts
            )

            if (
                updated_attempts
                >= self.max_failed_attempts
            ):

                self.lock_vault(
                    email
                )

                event_bus.publish(
                    {
                        "event_type":
                        "AUTH_BRUTE_FORCE",

                        "email": email,
                        "severity": "CRITICAL",
                        "timestamp": time.time(),
                    }
                )
                runtime_state.update(vault_locked=True, authenticated=False)

        except Exception as error:

            logger.exception(
                "Failed Attempt Error: %s",
                error
            )

    # =====================================================
    # Reset Failed Attempts
    # =====================================================

    def reset_failed_attempts(
        self,
        email: str
    ) -> None:

        try:

            supabase.table("auth").update(
                {
                    "failed_attempts": 0
                }
            ).eq(
                "email",
                email
            ).execute()

        except Exception as error:

            logger.exception(
                "Reset Attempt Error: %s",
                error
            )

    # =====================================================
    # Update Last Login
    # =====================================================

    def update_last_login(
        self,
        email: str
    ) -> None:

        try:

            from datetime import (
                datetime
            )

            supabase.table("auth").update(
                {
                    "last_login":
                    datetime.utcnow()
                    .isoformat()
                }
            ).eq(
                "email",
                email
            ).execute()

        except Exception as error:

            logger.exception(
                "Last Login Update Error: %s",
                error
            )

    # =====================================================
    # Vault Lock
    # =====================================================

    def lock_vault(
        self,
        email: str
    ) -> None:

        try:

            supabase.table("auth").update(
                {
                    "vault_locked": True
                }
            ).eq(
                "email",
                email
            ).execute()

            logger.warning(
                "Vault locked for %s",
                email
            )
            runtime_state.update(vault_locked=True)
            activate_vault_lock("OTP brute-force lock")

        except Exception as error:

            logger.exception(
                "Vault Lock Error: %s",
                error
            )


otp_manager = OTPManager()
