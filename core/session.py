import logging

logger = logging.getLogger("ATLAS-Session")


class Session:
    def __init__(self):
        self._email = None

    def set_user(self, email: str) -> None:
        self._email = email
        logger.info("Session set for user: %s", email)

    def get_email(self) -> str:
        return self._email

    def clear(self) -> None:
        logger.info("Session cleared for user: %s", self._email)
        self._email = None


session = Session()
