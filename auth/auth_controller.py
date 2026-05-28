"""
ATLAS Authentication Controller

Handles:
- Login flow
- OTP request flow
- OTP verification routing
- Authentication event orchestration
- Session state
"""
from typing import Optional

from config.logging_config import get_logger
from auth.otp_manager import (
    otp_manager
)

from monitor.event_bus import (
    event_bus
)
logger = get_logger("auth")


class AuthController:

    def __init__(self):

        self.current_user = None

        self.authenticated = False

    # =====================================================
    # Start Login Flow
    # =====================================================

    def start_login(
        self,
        email: str
    ) -> bool:

        logger.info(
            "Starting login flow for %s",
            email
        )

        success = (
            otp_manager.send_email_otp(
                email
            )
        )

        if success:

            event_bus.publish(
                {
                    "event_type":
                    "LOGIN_STARTED",

                    "email": email,
                }
            )

            logger.info(
                "OTP flow initiated"
            )

            return True

        logger.warning(
            "OTP flow failed"
        )

        return False

    # =====================================================
    # Verify Login OTP
    # =====================================================

    def verify_login(
        self,
        email: str,
        otp: str
    ) -> bool:

        logger.info(
            "Verifying OTP for %s",
            email
        )

        verified = (
            otp_manager.verify_email_otp(
                email,
                otp
            )
        )

        if verified:

            self.current_user = email

            self.authenticated = True

            event_bus.publish(
                {
                    "event_type":
                    "LOGIN_SUCCESS",

                    "email": email,
                }
            )

            logger.info(
                "Authentication success"
            )

            return True

        self.authenticated = False

        event_bus.publish(
            {
                "event_type":
                "LOGIN_FAILED",

                "email": email,
            }
        )

        logger.warning(
            "Authentication failed"
        )

        return False

    # =====================================================
    # Logout
    # =====================================================

    def logout(
        self
    ) -> None:

        if self.current_user:

            logger.info(
                "Logging out %s",
                self.current_user
            )

        self.current_user = None

        self.authenticated = False

        event_bus.publish(
            {
                "event_type": "LOGOUT"
            }
        )

    # =====================================================
    # Session State
    # =====================================================

    def is_authenticated(
        self
    ) -> bool:

        return self.authenticated

    def get_current_user(
        self
    ) -> Optional[str]:

        return self.current_user


auth_controller = AuthController()