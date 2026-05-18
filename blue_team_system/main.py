"""
Legacy compatibility shim.

`blue_team_system/main.py` is deprecated.
Canonical runtime is `ATLAS/main.py`.
"""

import sys
from pathlib import Path


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))

    print(
        "[DEPRECATED] blue_team_system runtime tree is disabled. "
        "Delegating to canonical launcher: ATLAS/main.py"
    )
    import main  # noqa: F401


if __name__ == "__main__":
    main()
