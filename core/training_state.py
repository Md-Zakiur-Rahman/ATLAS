"""
Shared training-state helpers for canonical ML state file.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict

TRAINING_STATE_PATH = Path("assets/training_state.json")


def load_training_state() -> Dict[str, Any]:
    if not TRAINING_STATE_PATH.exists():
        return {}
    try:
        return json.loads(TRAINING_STATE_PATH.read_text(encoding="utf-8"))
    except Exception:
        return {}

