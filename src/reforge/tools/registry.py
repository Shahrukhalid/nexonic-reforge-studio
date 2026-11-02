"""Tool registry: loads the 85-entry catalog and computes *live* status per host.

Status is always computed from what is actually present on this machine; the
catalog never asserts that a tool is installed.
"""
from __future__ import annotations

import importlib.metadata
import importlib.util
import json
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

BUNDLED_PY = {"lief"}            # shipped inside the installer
BUILTIN = {"builtin"}            # implemented natively by ReForge


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
            loc = shutil.which(exe)
            if loc:
                return ToolStatus(e, S_INSTALLED, None, loc)
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
        if loc := shutil.which(exe):
            return loc
    return None


def summary() -> dict[str, int]:
    out: dict[str, int] = {}
    for s in all_status():
        out[s.status] = out.get(s.status, 0) + 1
    return out
