import logging
import os
from logging.handlers import RotatingFileHandler

LOG_DIR = "D:\\logs"
os.makedirs(LOG_DIR, exist_ok=True)

LOG_FORMAT = "%(asctime)s | %(levelname)-8s | %(name)-12s | %(message)s"

_loggers = {}


def get_logger(name: str) -> logging.Logger:
    """
    Factory function for creating and configuring loggers.
    Ensures that handlers are not added multiple times.
    """
    if name in _loggers:
        return _loggers[name]

    # Determine the log file based on the logger name/category
    log_file = os.path.join(LOG_DIR, f"{name}.log")

    # Create the logger
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)

    # Prevent logs from propagating to the root logger
    logger.propagate = False

    # Create a rotating file handler
    handler = RotatingFileHandler(
        log_file,
        maxBytes=10 * 1024 * 1024,  # 10MB
        backupCount=5,
        encoding="utf-8",
    )

    # Create a formatter and set it for the handler
    formatter = logging.Formatter(LOG_FORMAT)
    handler.setFormatter(formatter)

    # Add the handler to the logger
    logger.addHandler(handler)

    _loggers[name] = logger
    return logger