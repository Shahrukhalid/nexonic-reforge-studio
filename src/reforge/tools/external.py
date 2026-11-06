"""Hand a file to an external GUI tool. ReForge never runs the analysed target itself."""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from . import registry


class ExternalToolError(RuntimeError):
    pass


def find_imhex() -> str | None:
    return registry.find_exe("ImHex")


def open_in_imhex(target: Path, workdir: Path | None = None) -> tuple[subprocess.Popen, Path]:
    """Open a *copy* of `target` in ImHex so edits made there can never change the original input."""
    exe = find_imhex()
    if not exe:
        raise ExternalToolError("ImHex is not installed (https://imhex.werwolv.net)")
    target = Path(target)
    if not target.is_file():
        raise ExternalToolError(f"ImHex opens single files; {target.name} is not a file")
    dest_dir = Path(workdir) / "imhex" if workdir else Path(tempfile.mkdtemp(prefix="reforge-imhex-"))
    dest_dir.mkdir(parents=True, exist_ok=True)
    copy = dest_dir / target.name
    shutil.copyfile(target, copy)
    kw: dict = {"stdin": subprocess.DEVNULL, "stdout": subprocess.DEVNULL, "stderr": subprocess.DEVNULL}
    if sys.platform == "win32":
        kw["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.DETACHED_PROCESS
    else:
        kw["start_new_session"] = True
    env = {k: v for k, v in os.environ.items() if not k.upper().endswith(("_API_KEY", "_TOKEN", "_SECRET"))}
    return subprocess.Popen([exe, str(copy)], env=env, shell=False, **kw), copy
