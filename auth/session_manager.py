"""
ATLAS Session Manager

Handles:
- Active user session state
- Login session tracking
- Logout cleanup
- Session validation
"""

import logging
from datetime import datetime
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
    "ATLAS-SessionManager"
)


class SessionManager:

    def __init__(self):

        self.current_user = None

        self.session_active = False

        self.login_time = None

    # =====================================================
    # Create Session
    # =====================================================

    def create_session(
        self,
        email: str
    ) -> None:

        self.current_user = email

        self.session_active = True

        self.login_time = (
            datetime.utcnow()
        )

        logger.info(
            "Session created for %s",
            email
        )

        event_bus.publish(
            {
                "type":
                "SESSION_CREATED",

                "email": email,
            }
        )

    # =====================================================
    # Destroy Session
    # =====================================================

    def destroy_session(
        self
    ) -> None:

        if self.current_user:

            logger.info(
                "Session destroyed for %s",
                self.current_user
            )

            event_bus.publish(
                {
                    "type":
                    "SESSION_DESTROYED",

                    "email":
                    self.current_user,
                }
            )

        self.current_user = None

        self.session_active = False

        self.login_time = None

    # =====================================================
    # Session State
    # =====================================================

    def is_authenticated(
        self
    ) -> bool:

        return self.session_active

    def get_current_user(
        self
    ) -> Optional[str]:

        return self.current_user

    def get_login_time(
        self
    ) -> Optional[datetime]:

        return self.login_time

    # =====================================================
    # Validate Session
    # =====================================================

    def validate_session(
        self
    ) -> bool:

        if not self.session_active:
            return False

        if not self.current_user:
            return False

        try:

            response = (
                supabase.table("auth")
                .select("email")
                .eq(
                    "email",
                    self.current_user
                )
                .execute()
            )

            if not response.data:

                logger.warning(
                    "Session validation failed"
                )

                self.destroy_session()

                return False

            return True

        except Exception as error:

            logger.exception(
                "Session Validation Error: %s",
                error
            )

            return False


session_manager = SessionManager()