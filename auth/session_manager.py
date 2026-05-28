"""
ATLAS Session Manager

Handles:
- Active user session state
- Login session tracking
- Logout cleanup
- Session validation
"""
from datetime import datetime
from typing import Optional

from config.logging_config import get_logger
from core.runtime_state import runtime_state
from core.session import session
from database.client import (
    supabase
)

from monitor.event_bus import (
    event_bus
)
logger = get_logger("auth")


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
        session.set_user(email)
        runtime_state.update(
            current_user=email,
            current_email=email,
            authenticated=True,
        )

        event_bus.publish(
            {
                "event_type":
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
                    "event_type":
                    "SESSION_DESTROYED",

                    "email":
                    self.current_user,
                }
            )

        self.current_user = None

        self.session_active = False

        self.login_time = None
        session.clear()
        runtime_state.update(
            current_user=None,
            current_email=None,
            authenticated=False,
            auth_method=None,
        )

    # =====================================================
    # Session State
    # =====================================================

    def is_authenticated(
        self
    ) -> bool:
        return bool(runtime_state.snapshot().get("authenticated"))

    def get_current_user(
        self
    ) -> Optional[str]:
        return runtime_state.snapshot().get("current_email")

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
