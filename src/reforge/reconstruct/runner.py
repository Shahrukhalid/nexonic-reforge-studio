"""Safe subprocess test and build runner for reconstructed projects."""
from __future__ import annotations

import shutil
import sys
from pathlib import Path

from ..core.safety import ToolResult, run_tool


def detect_runner_commands(project_dir: Path) -> dict[str, list[str]]:
    """Detect available test and build commands based on project files."""
    cmds: dict[str, list[str]] = {}
    if (project_dir / "pyproject.toml").is_file() or (project_dir / "setup.py").is_file():
        cmds["test"] = [sys.executable, "-m", "pytest", "-v"]
        cmds["build"] = [sys.executable, "-m", "pip", "install", "-e", "."]
    elif (project_dir / "package.json").is_file():
        npm = shutil.which("npm") or shutil.which("npm.cmd") or "npm"
        cmds["test"] = [npm, "test"]
        cmds["build"] = [npm, "run", "build"]
    elif (project_dir / "Cargo.toml").is_file():
        cargo = shutil.which("cargo") or "cargo"
        cmds["test"] = [cargo, "test"]
        cmds["build"] = [cargo, "build"]
    elif (project_dir / "go.mod").is_file():
        go = shutil.which("go") or "go"
        cmds["test"] = [go, "test", "./..."]
        cmds["build"] = [go, "build", "."]
    else:
        # Default Python test runner fallback if .py files exist
        if any(project_dir.rglob("*.py")):
            cmds["test"] = [sys.executable, "-m", "pytest", "-v"]
    return cmds


def run_project_tests(project_dir: Path, timeout: int = 120) -> ToolResult:
    """Run automated tests inside the clean-room project directory."""
    cmds = detect_runner_commands(project_dir)
    if "test" not in cmds:
        return ToolResult(
            argv=[], returncode=1, stdout="",
            stderr="No supported test runner found (missing pyproject.toml, package.json, Cargo.toml, or go.mod).",
            duration=0.0
        )
    return run_tool(cmds["test"], cwd=project_dir, timeout=timeout)


def run_project_build(project_dir: Path, timeout: int = 180) -> ToolResult:
    """Run build command inside the clean-room project directory."""
    cmds = detect_runner_commands(project_dir)
    if "build" not in cmds:
        return ToolResult(
            argv=[], returncode=1, stdout="",
            stderr="No supported build command found.",
            duration=0.0
        )
    return run_tool(cmds["build"], cwd=project_dir, timeout=timeout)
