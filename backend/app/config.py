from __future__ import annotations

import os
from pathlib import Path

BACKEND_ROOT = Path(__file__).resolve().parents[1]
PROJECT_ROOT = BACKEND_ROOT.parent
FIXTURE_ROOT = BACKEND_ROOT / "fixtures"
DEFAULT_DB_PATH = BACKEND_ROOT / "data" / "vulnorbit.db"


def database_path() -> Path:
    return Path(os.environ.get("VULNORBIT_DB_PATH", DEFAULT_DB_PATH)).expanduser()
