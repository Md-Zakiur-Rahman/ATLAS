"""
ATLAS Rename Log

Tracks file rename activity and
supports rollback restoration.
"""

import os
from collections import deque
from typing import Deque, Dict

from config.logging_config import get_logger
from monitor.event_bus import (
    event_bus
)
logger = get_logger("events")


class RenameLog:

    def __init__(self):

        self.rename_history: Deque[
            Dict
        ] = deque(
            maxlen=5000
        )

        event_bus.subscribe(
            self.process_event
        )

    def process_event(
        self,
        event: Dict
    ) -> None:

        if (
            event.get("event_type")
            != "FILE_RENAMED"
        ):
            return

        old_path = event.get(
            "old_path"
        )

        new_path = event.get(
            "path"
        )

        if (
            not old_path
            or not new_path
        ):
            return

        rename_entry = {

            "old_path": old_path,

            "new_path": new_path,
        }

        self.rename_history.append(
            rename_entry
        )

        logger.info(
            "Rename Logged: %s -> %s",
            old_path,
            new_path,
        )

    def rollback(
        self
    ) -> None:
        """
        Restore renamed files.
        """

        logger.warning(
            "Starting Rename Rollback"
        )

        rollback_count = 0

        for entry in reversed(
            self.rename_history
        ):

            old_path = entry[
                "old_path"
            ]

            new_path = entry[
                "new_path"
            ]

            try:

                if os.path.exists(
                    new_path
                ):

                    os.rename(
                        new_path,
                        old_path
                    )

                    rollback_count += 1

                    logger.warning(
                        "Rollback Success: "
                        "%s -> %s",
                        new_path,
                        old_path,
                    )

            except Exception as error:

                logger.error(
                    "Rollback Failed: %s",
                    error
                )

        logger.warning(
            "Rollback Complete | "
            "%s Files Restored",
            rollback_count,
        )


rename_log = RenameLog()