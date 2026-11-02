"""Locate a JDK of a required major version (Ghidra needs 21+).

Searches JAVA_HOME, macOS java_home, Homebrew, common Linux/Windows locations,
then PATH. Each candidate is verified by running `java -version`.
"""
from __future__ import annotations

import glob
import os
import re
import shutil
import subprocess
import sys
from functools import lru_cache
from pathlib import Path

VERSION_RE = re.compile(r'version "(\d+)(?:\.(\d+))?')


def _java_bin(home: Path) -> Path:
    return home / "bin" / ("java.exe" if os.name == "nt" else "java")


def java_major(java: str | Path) -> int | None:
    try:
        r = subprocess.run([str(java), "-version"], capture_output=True, timeout=20, stdin=subprocess.DEVNULL)
    except (OSError, subprocess.TimeoutExpired):
        return None
    m = VERSION_RE.search((r.stderr or r.stdout).decode(errors="replace"))
    if not m:
        return None
    major = int(m.group(1))
    return int(m.group(2) or 0) if major == 1 else major   # "1.8.0" -> 8


def _candidates() -> list[Path]:
    c: list[Path] = []
    if os.environ.get("JAVA_HOME"):
        c.append(Path(os.environ["JAVA_HOME"]))
    if sys.platform == "darwin":
        try:
            r = subprocess.run(["/usr/libexec/java_home", "-v", "21+"], capture_output=True, timeout=10)
            if r.returncode == 0 and r.stdout.strip():
                c.append(Path(r.stdout.decode().strip()))
        except (OSError, subprocess.TimeoutExpired):
            pass
        for prefix in ("/opt/homebrew", "/usr/local"):
            for pat in ("opt/openjdk@2[1-9]/libexec/openjdk.jdk/Contents/Home", "opt/openjdk/libexec/openjdk.jdk/Contents/Home"):
                c += [Path(p) for p in sorted(glob.glob(f"{prefix}/{pat}"), reverse=True)]
        c += [Path(p) for p in sorted(glob.glob("/Library/Java/JavaVirtualMachines/*/Contents/Home"), reverse=True)]
    elif os.name == "nt":
        for base in (os.environ.get("ProgramFiles", r"C:\Program Files"),):
            for vendor in ("Eclipse Adoptium", "Java", "Microsoft", "Zulu", "Amazon Corretto"):
                c += [Path(p) for p in sorted(glob.glob(os.path.join(base, vendor, "jdk-2*")), reverse=True)]
    else:
        c += [Path(p) for p in sorted(glob.glob("/usr/lib/jvm/*"), reverse=True)]
    on_path = shutil.which("java")
    if on_path:
        c.append(Path(on_path).resolve().parent.parent)
    seen, out = set(), []
    for p in c:
        if p not in seen:
            seen.add(p)
            out.append(p)
    return out


@lru_cache(maxsize=4)
def find_jdk(min_major: int = 21) -> tuple[Path, int] | None:
    """Return (JAVA_HOME, major) for the first JDK >= min_major, else None."""
    for home in _candidates():
        jb = _java_bin(home)
        if jb.is_file():
            major = java_major(jb)
            if major and major >= min_major:
                return home, major
    return None


def env_for(home: Path) -> dict[str, str]:
    return {"JAVA_HOME": str(home), "PATH": str(home / "bin") + os.pathsep + os.environ.get("PATH", "")}
