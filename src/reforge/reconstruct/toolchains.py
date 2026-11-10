"""Host compiler and build toolchain discovery for reconstructed clean-room projects."""
from __future__ import annotations

import re
import shutil
import sys
from dataclasses import asdict, dataclass
from typing import Any

from ..core.safety import run_tool


@dataclass
class HostToolchain:
    id: str
    name: str
    category: str  # "compiler", "runtime", "build_system", "package_manager"
    executable: str
    available: bool
    version: str = ""
    supported_targets: list[str] | None = None
    path: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


_TOOLCHAIN_DEFINITIONS = [
    {
        "id": "python",
        "name": "Python Runtimes & PyInstaller",
        "category": "runtime",
        "candidates": [sys.executable, "python3", "python"],
        "version_flag": ["--version"],
        "version_regex": r"Python\s+([0-9]+\.[0-9]+\.[0-9]+)",
        "targets": ["win-x64", "macos-arm64", "macos-x64", "linux-x64"],
    },
    {
        "id": "cargo",
        "name": "Rust Toolchain (Cargo / rustc)",
        "category": "compiler",
        "candidates": ["cargo", "rustc"],
        "version_flag": ["--version"],
        "version_regex": r"cargo\s+([0-9]+\.[0-9]+\.[0-9]+)",
        "targets": ["win-x64", "macos-arm64", "macos-x64", "linux-x64"],
    },
    {
        "id": "go",
        "name": "Go Compiler",
        "category": "compiler",
        "candidates": ["go"],
        "version_flag": ["version"],
        "version_regex": r"go\s+version\s+go([0-9]+\.[0-9]+(?:\.[0-9]+)?)",
        "targets": ["win-x64", "macos-arm64", "macos-x64", "linux-x64"],
    },
    {
        "id": "dotnet",
        "name": ".NET SDK (C# / F# / VB)",
        "category": "compiler",
        "candidates": ["dotnet"],
        "version_flag": ["--version"],
        "version_regex": r"([0-9]+\.[0-9]+\.[0-9]+)",
        "targets": ["win-x64", "macos-arm64", "macos-x64", "linux-x64"],
    },
    {
        "id": "javac",
        "name": "Java Development Kit (javac)",
        "category": "compiler",
        "candidates": ["javac"],
        "version_flag": ["-version"],
        "version_regex": r"javac\s+([0-9]+(?:\.[0-9]+)*)",
        "targets": ["jvm", "jar"],
    },
    {
        "id": "maven",
        "name": "Apache Maven",
        "category": "build_system",
        "candidates": ["mvn", "mvn.cmd"],
        "version_flag": ["-version"],
        "version_regex": r"Apache\s+Maven\s+([0-9]+\.[0-9]+\.[0-9]+)",
        "targets": ["jvm", "jar"],
    },
    {
        "id": "cmake",
        "name": "CMake Meta-Build System",
        "category": "build_system",
        "candidates": ["cmake"],
        "version_flag": ["--version"],
        "version_regex": r"cmake\s+version\s+([0-9]+\.[0-9]+\.[0-9]+)",
        "targets": ["native_binary", "shared_lib"],
    },
    {
        "id": "gcc",
        "name": "GNU Compiler Collection (GCC)",
        "category": "compiler",
        "candidates": ["gcc", "x86_64-w64-mingw32-gcc"],
        "version_flag": ["--version"],
        "version_regex": r"gcc.*?\s+([0-9]+\.[0-9]+\.[0-9]+)",
        "targets": ["native_binary", "shared_lib"],
    },
    {
        "id": "clang",
        "name": "LLVM Clang Compiler",
        "category": "compiler",
        "candidates": ["clang"],
        "version_flag": ["--version"],
        "version_regex": r"clang\s+version\s+([0-9]+\.[0-9]+\.[0-9]+)",
        "targets": ["native_binary", "shared_lib"],
    },
    {
        "id": "npm",
        "name": "Node.js & npm (TypeScript)",
        "category": "package_manager",
        "candidates": ["npm", "npm.cmd"],
        "version_flag": ["--version"],
        "version_regex": r"([0-9]+\.[0-9]+\.[0-9]+)",
        "targets": ["node", "web", "electron"],
    },
]

_CACHE_TOOLCHAINS: dict[str, HostToolchain] | None = None


def detect_host_toolchains(force_refresh: bool = False) -> dict[str, HostToolchain]:
    """Inspect and return all available native compiler and build toolchains on the host."""
    global _CACHE_TOOLCHAINS
    if _CACHE_TOOLCHAINS is not None and not force_refresh:
        return _CACHE_TOOLCHAINS

    toolchains: dict[str, HostToolchain] = {}

    for defn in _TOOLCHAIN_DEFINITIONS:
        tid = defn["id"]
        found_exe: str | None = None

        for cand in defn["candidates"]:
            # If path exists or on PATH
            if shutil.which(cand) or (sys.platform == "win32" and shutil.which(f"{cand}.exe")):
                found_exe = shutil.which(cand) or shutil.which(f"{cand}.exe")
                break
            elif cand == sys.executable:
                found_exe = cand
                break

        if not found_exe:
            toolchains[tid] = HostToolchain(
                id=tid,
                name=defn["name"],
                category=defn["category"],
                executable=defn["candidates"][0],
                available=False,
                version="",
                supported_targets=defn["targets"],
                path="",
            )
            continue

        # Probe version safely
        version = ""
        res = run_tool([found_exe] + defn["version_flag"], timeout=5)
        out = (res.stdout + "\n" + res.stderr).strip()
        m = re.search(defn["version_regex"], out, re.IGNORECASE)
        if m:
            version = m.group(1)
        elif res.ok and out:
            # Fallback to first line
            version = out.splitlines()[0][:30]

        toolchains[tid] = HostToolchain(
            id=tid,
            name=defn["name"],
            category=defn["category"],
            executable=found_exe,
            available=True,
            version=version or "detected",
            supported_targets=defn["targets"],
            path=found_exe,
        )

    _CACHE_TOOLCHAINS = toolchains
    return toolchains
