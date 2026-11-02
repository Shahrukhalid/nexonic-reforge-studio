"""Shared tool-setup actions used by both the CLI and the GUI (Tool Manager)."""
from __future__ import annotations

import os
import shutil
import subprocess
from collections.abc import Callable

from . import jdk, registry
from .adapters.ghidra import DEFAULT_JAVA_MIN, decompiler_native, ghidra_root, native_platform, required_java


def ghidra_status() -> dict:
    exe = registry.find_exe("Ghidra")
    need = required_java(exe) if exe else DEFAULT_JAVA_MIN
    j = jdk.find_jdk(need)
    d = decompiler_native(exe) if exe else None
    return {"installed": bool(exe), "exe": exe, "java_required": need,
            "java": f"{j[1]} ({j[0]})" if j else None, "platform": native_platform(),
            "decompiler": str(d) if d and d.is_file() else None}


def build_ghidra_natives(log: Callable[[str], None] = print) -> bool:
    """Run Ghidra's own native build (support/gradle: gradle|gradlew buildNatives). Returns success."""
    exe = registry.find_exe("Ghidra")
    if not exe:
        log("Ghidra is not installed.")
        return False
    gdir = ghidra_root(exe) / "support" / "gradle"
    if not gdir.is_dir():
        log(f"not found: {gdir}")
        return False
    found = jdk.find_jdk(required_java(exe))
    if not found:
        log(f"JDK {required_java(exe)}+ not found.")
        return False
    wrapper = gdir / ("gradlew.bat" if os.name == "nt" else "gradlew")
    if shutil.which("gradle"):
        cmd = ["gradle", "buildNatives"]
    elif wrapper.is_file():
        cmd = [str(wrapper), "buildNatives"] if os.name == "nt" else ["sh", str(wrapper), "buildNatives"]
    else:
        log("Neither 'gradle' nor Ghidra's gradlew wrapper found; install Gradle 9.1+.")
        return False
    log(f"Building Ghidra native components in {gdir} (takes a few minutes)...")
    proc = subprocess.Popen(cmd, cwd=str(gdir), env={**os.environ, **jdk.env_for(found[0])},
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, stdin=subprocess.DEVNULL)
    assert proc.stdout is not None
    for line in proc.stdout:
        log(line.rstrip())
    proc.wait()
    ok = decompiler_native(exe).is_file()
    log("decompiler: " + (f"OK {decompiler_native(exe)}" if ok else "still missing (see output above)"))
    return ok
