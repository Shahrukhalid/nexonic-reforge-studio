"""Tool registry: loads the 85-entry catalog and computes *live* status per host.

Status is always computed from what is actually present on this machine; the
catalog never asserts that a tool is installed.
"""
from __future__ import annotations

import importlib.metadata
import importlib.util
import json
import os
import shutil
import sys
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

REGISTRY_FILE = Path(__file__).with_name("registry.json")

S_BUNDLED = "Bundled and operational"
S_INSTALLED = "Installed and operational"
S_OPTIONAL = "Optional integration"
S_PAID = "External paid dependency required"
S_UNSUPPORTED = "Unsupported on current operating system"
S_DEPRECATED = "Deprecated or unmaintained"
S_PENDING = "Installation pending"
S_FAILED = "Verification failed"

BUNDLED_PY = {"lief", "capstone"}            # shipped inside the installer
BUILTIN = {"builtin"}            # implemented natively by ReForge


def _which(exe: str) -> str | None:
    from . import toolpacks  # local import: avoids an import cycle at module load
    extra = toolpacks.bin_dirs()
    if extra:
        found = shutil.which(exe, path=os.pathsep.join(extra))
        if found:
            return found
    found = shutil.which(exe)
    if found:
        return found
    for cand in APP_PATHS.get(exe, {}).get(host_os(), []):
        path = Path(os.path.expandvars(os.path.expanduser(cand)))
        if path.is_file():
            return str(path)
    return None


# GUI tools that install outside PATH (app bundles, Program Files).
APP_PATHS = {
    "imhex": {
        "macos": ["/Applications/ImHex.app/Contents/MacOS/imhex", "~/Applications/ImHex.app/Contents/MacOS/imhex"],
        "windows": [r"%ProgramFiles%\ImHex\imhex-gui.exe", r"%ProgramFiles%\ImHex\imhex.exe",
                    r"%LOCALAPPDATA%\Programs\ImHex\imhex-gui.exe"],
    },
}


def host_os() -> str:
    return {"darwin": "macos", "win32": "windows"}.get(sys.platform, "linux")


@dataclass
class ToolStatus:
    entry: dict
    status: str
    version: str | None = None
    location: str | None = None

    @property
    def available(self) -> bool:
        return self.status in (S_BUNDLED, S_INSTALLED)


@lru_cache(maxsize=1)
def load() -> list[dict]:
    return json.loads(REGISTRY_FILE.read_text())


def by_name(name: str) -> dict | None:
    return next((e for e in load() if e["name"].lower() == name.lower()), None)


def _py_version(mod: str) -> str | None:
    for dist in (mod, mod.replace("_", "-")):
        try:
            return importlib.metadata.version(dist)
        except importlib.metadata.PackageNotFoundError:
            continue
    return "present"


_VERSION_CACHE: dict[str, str | None] = {}


def _bin_version(name: str, exe: str) -> str | None:
    if exe in _VERSION_CACHE:
        return _VERSION_CACHE[exe]
    from ..core.safety import run_tool
    ver: str | None = None
    flags = ["--version", "-version", "-v", "version"]
    if "ghidra" in name.lower():
        p = Path(exe).parent.parent / "Ghidra" / "application.properties"
        if p.is_file():
            for line in p.read_text(errors="replace").splitlines():
                if line.startswith("application.version="):
                    ver = line.split("=", 1)[1].strip()
                    break
    if not ver:
        for flag in flags:
            res = run_tool([exe, flag], timeout=2, max_output=4096)
            out = (res.stdout or res.stderr).strip()
            if out:
                import re
                m = re.search(r"\b(\d+\.\d+(?:\.\d+)?)\b", out)
                if m:
                    ver = m.group(1)
                    break
    _VERSION_CACHE[exe] = ver
    return ver


def status_of(e: dict) -> ToolStatus:
    if host_os() not in e["platforms"]:
        return ToolStatus(e, S_UNSUPPORTED)
    if e["verification"] == "failed":
        return ToolStatus(e, S_FAILED)
    det = e.get("detect") or ""
    if det in BUILTIN:
        return ToolStatus(e, S_BUNDLED, "native", "reforge")
    if det.startswith("py:"):
        mod = det[3:]
        if importlib.util.find_spec(mod) is not None:
            st = S_BUNDLED if mod in BUNDLED_PY else S_INSTALLED
            return ToolStatus(e, st, _py_version(mod), mod)
    elif det.startswith("bin:"):
        for exe in det[4:].split("|"):
            loc = _which(exe)
            if loc:
                ver = _bin_version(e["name"], loc)
                return ToolStatus(e, S_INSTALLED, ver, loc)
    if e["integration"] == "paid-host":
        return ToolStatus(e, S_PAID)
    if e.get("archived") or e.get("maintained") is False:
        return ToolStatus(e, S_DEPRECATED)
    if e["integration"] in ("reference-only", "plugin-host", "external-app") or not det:
        return ToolStatus(e, S_OPTIONAL)
    return ToolStatus(e, S_PENDING)


def all_status() -> list[ToolStatus]:
    return [status_of(e) for e in load()]


def find_exe(name: str) -> str | None:
    e = by_name(name)
    if not e or not e["detect"].startswith("bin:"):
        return None
    for exe in e["detect"][4:].split("|"):
        if loc := _which(exe):
            return loc
    return None


def summary() -> dict[str, int]:
    out: dict[str, int] = {}
    for s in all_status():
        out[s.status] = out.get(s.status, 0) + 1
    return out
