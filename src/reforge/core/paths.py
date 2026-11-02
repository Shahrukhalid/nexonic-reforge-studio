"""Per-user application data locations (overridable with REFORGE_HOME)."""
from __future__ import annotations

import os
import sys
from pathlib import Path

APP_DIR = "NexonicReForge"


def data_dir() -> Path:
    env = os.environ.get("REFORGE_HOME")
    if env:
        p = Path(env)
    elif sys.platform == "darwin":
        p = Path.home() / "Library" / "Application Support" / APP_DIR
    elif os.name == "nt":
        p = Path(os.environ.get("APPDATA", str(Path.home()))) / APP_DIR
    else:
        p = Path(os.environ.get("XDG_DATA_HOME", str(Path.home() / ".local" / "share"))) / APP_DIR
    p.mkdir(parents=True, exist_ok=True)
    return p


def projects_dir() -> Path:
    p = data_dir() / "projects"
    p.mkdir(parents=True, exist_ok=True)
    return p


def db_path() -> Path:
    return data_dir() / "reforge.sqlite3"


def log_path() -> Path:
    return data_dir() / "reforge.log"
