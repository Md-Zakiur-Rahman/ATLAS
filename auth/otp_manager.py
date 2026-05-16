"""
ATLAS Supabase Email OTP Manager

Handles:
- Email OTP requests
- OTP verification
- AUTH_SUCCESS events
- AUTH_FAIL events
- Failed attempt tracking
"""

import logging
from typing import Optional

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
    "ATLAS-OTPManager"
)


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
                    "email": email,

                    "options": {
                                "should_create_user": True
                                }
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
                    "type": "AUTH_FAIL",

                    "email": email,

                    "reason": (
                        "OTP_SEND_FAILED"
                    ),
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
                        "type": "AUTH_FAIL",

                        "email": email,

                        "reason": (
                            "INVALID_OTP"
                        ),
                    }
                )

                logger.warning(
                    "OTP verification failed"
                )

                return False

            self.reset_failed_attempts(
                email
            )

            self.update_last_login(
                email
            )

            event_bus.publish(
                {
                    "type": "AUTH_SUCCESS",

                    "email": email,
                }
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
                    "type": "AUTH_FAIL",

                    "email": email,

                    "reason": (
                        "OTP_EXCEPTION"
                    ),
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
                        "type":
                        "AUTH_BRUTE_FORCE",

                        "email": email,
                    }
                )

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

        except Exception as error:

            logger.exception(
                "Vault Lock Error: %s",
                error
            )


otp_manager = OTPManager()