"""Safe subprocess test and build runner for reconstructed projects."""
from __future__ import annotations

import os
import re
import shutil
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from ..core.safety import ToolResult, run_tool


@dataclass
class TestExecutionSummary:
    ok: bool
    total: int
    passed: int
    failed: int
    skipped: int
    duration: float
    stdout: str
    stderr: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def parse_test_summary(stdout: str, stderr: str, returncode: int, duration: float) -> TestExecutionSummary:
    """Parse output from pytest, cargo, go, dotnet, maven, or ctest into structured metrics."""
    passed = 0
    failed = 0
    skipped = 0
    combined = f"{stdout}\n{stderr}"

    # 1. Pytest patterns: "5 passed, 1 failed, 2 skipped in 0.42s"
    m_pass = re.search(r"(\d+)\s+passed", combined)
    m_fail = re.search(r"(\d+)\s+failed", combined)
    m_skip = re.search(r"(\d+)\s+skipped", combined)
    if m_pass:
        passed = int(m_pass.group(1))
    if m_fail:
        failed = int(m_fail.group(1))
    if m_skip:
        skipped = int(m_skip.group(1))

    # 2. Cargo test: "test result: ok. 4 passed; 0 failed; 1 ignored;"
    m_cargo = re.search(r"test result:\s*\w+\.\s*(\d+)\s*passed;\s*(\d+)\s*failed;\s*(\d+)\s*ignored", combined)
    if m_cargo:
        passed = int(m_cargo.group(1))
        failed = int(m_cargo.group(2))
        skipped = int(m_cargo.group(3))

    # 3. .NET test: "Passed: 4, Failed: 0, Skipped: 0, Total: 4"
    m_net_pass = re.search(r"Passed:\s*(\d+)", combined)
    m_net_fail = re.search(r"Failed:\s*(\d+)", combined)
    m_net_skip = re.search(r"Skipped:\s*(\d+)", combined)
    if m_net_pass and not m_pass and not m_cargo:
        passed = int(m_net_pass.group(1))
        if m_net_fail:
            failed = int(m_net_fail.group(1))
        if m_net_skip:
            skipped = int(m_net_skip.group(1))

    # 4. Maven Surefire: "Tests run: 5, Failures: 0, Errors: 0, Skipped: 0"
    m_mvn = re.search(r"Tests run:\s*(\d+),\s*Failures:\s*(\d+),\s*Errors:\s*(\d+),\s*Skipped:\s*(\d+)", combined)
    if m_mvn:
        total_run = int(m_mvn.group(1))
        failures = int(m_mvn.group(2)) + int(m_mvn.group(3))
        skipped = int(m_mvn.group(4))
        failed = failures
        passed = max(0, total_run - failures - skipped)

    # 5. Go test: count "--- PASS:" and "--- FAIL:"
    if "--- PASS:" in combined or "--- FAIL:" in combined:
        go_pass = len(re.findall(r"---\s+PASS:", combined))
        go_fail = len(re.findall(r"---\s+FAIL:", combined))
        if go_pass > 0 or go_fail > 0:
            passed = go_pass
            failed = go_fail

    # Fallback if returncode == 0 but no counts parsed
    if returncode == 0 and (passed + failed + skipped == 0):
        if "pass" in combined.lower() or "ok" in combined.lower():
            passed = 1

    total = passed + failed + skipped
    ok = (returncode == 0) and (failed == 0)

    return TestExecutionSummary(
        ok=ok,
        total=total,
        passed=passed,
        failed=failed,
        skipped=skipped,
        duration=duration,
        stdout=stdout,
        stderr=stderr,
    )


def detect_runner_commands(project_dir: Path) -> dict[str, list[str]]:
    """Detect available test and build commands based on project files."""
    cmds: dict[str, list[str]] = {}
    src_dir = project_dir / "src"
    py_test_cmd = [sys.executable, "-m", "pytest", "-v"]
    if src_dir.is_dir():
        py_test_cmd = [sys.executable, "-m", "pytest", "-o", "pythonpath=src", "-v"]

    if (project_dir / "pyproject.toml").is_file() or (project_dir / "setup.py").is_file():
        cmds["test"] = py_test_cmd
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
    elif list(project_dir.glob("*.csproj")) or list(project_dir.glob("*.sln")):
        dotnet = shutil.which("dotnet") or "dotnet"
        cmds["test"] = [dotnet, "test"]
        cmds["build"] = [dotnet, "build"]
    elif (project_dir / "pom.xml").is_file():
        mvn = shutil.which("mvn") or shutil.which("mvn.cmd") or "mvn"
        cmds["test"] = [mvn, "test"]
        cmds["build"] = [mvn, "compile"]
    elif (project_dir / "build.gradle").is_file():
        gradle = shutil.which("gradle") or shutil.which("gradle.bat") or "gradle"
        cmds["test"] = [gradle, "test"]
        cmds["build"] = [gradle, "build"]
    elif (project_dir / "CMakeLists.txt").is_file():
        cmake = shutil.which("cmake") or "cmake"
        ctest = shutil.which("ctest") or "ctest"
        cmds["build"] = [cmake, "--build", "dist/cmake_build", "--config", "Release"]
        cmds["test"] = [ctest, "--test-dir", "dist/cmake_build", "--output-on-failure"]
    else:
        # Default Python test runner fallback if .py files exist
        if any(project_dir.rglob("*.py")):
            cmds["test"] = py_test_cmd
    return cmds


def run_project_tests(project_dir: Path, timeout: int = 120) -> ToolResult:
    """Run automated tests inside the clean-room project directory."""
    cmds = detect_runner_commands(project_dir)
    if "test" not in cmds:
        return ToolResult(
            argv=[],
            returncode=1,
            stdout="",
            stderr="No supported test runner found (missing pyproject.toml, package.json, Cargo.toml, go.mod, *.csproj, pom.xml, or CMakeLists.txt).",
            duration=0.0,
        )
    extra_env: dict[str, str] = {}
    src_path = str(project_dir / "src")
    if (project_dir / "src").is_dir():
        cur_pp = os.environ.get("PYTHONPATH", "")
        extra_env["PYTHONPATH"] = f"{src_path}{os.pathsep}{cur_pp}" if cur_pp else src_path
    return run_tool(cmds["test"], cwd=project_dir, timeout=timeout, extra_env=extra_env)


def run_project_tests_with_summary(project_dir: Path, timeout: int = 120) -> TestExecutionSummary:
    """Execute tests and return a structured TestExecutionSummary."""
    res = run_project_tests(project_dir, timeout=timeout)
    return parse_test_summary(res.stdout, res.stderr, res.returncode, res.duration)


def run_project_build(project_dir: Path, timeout: int = 180) -> ToolResult:
    """Run build command inside the clean-room project directory."""
    cmds = detect_runner_commands(project_dir)
    if "build" not in cmds:
        return ToolResult(
            argv=[],
            returncode=1,
            stdout="",
            stderr="No supported build command found.",
            duration=0.0,
        )
    return run_tool(cmds["build"], cwd=project_dir, timeout=timeout)
