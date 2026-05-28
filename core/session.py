from config.logging_config import get_logger
from core.runtime_state import runtime_state

logger = get_logger("auth")


class Session:
    def set_user(self, email: str) -> None:
        runtime_state.update(
            current_user=email,
            current_email=email,
            authenticated=True,
        )
        logger.info("Session set for user: %s", email)

    def get_email(self) -> str:
        return runtime_state.snapshot().get("current_email")

    def clear(self) -> None:
        logger.info("Session cleared for user: %s", self.get_email())
        runtime_state.update(
            current_user=None,
            current_email=None,
            authenticated=False,
            auth_method=None,
        )


session = Session()
