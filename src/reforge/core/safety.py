"""Untrusted-input safety primitives: limits, path containment, subprocess runner.

Nothing in this module ever executes the *target* application. `run_tool` only
runs analysis tools from the registry, with an argument list (never a shell),
a timeout and an output cap.
"""
from __future__ import annotations

import os
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path, PurePosixPath


@dataclass
class Limits:
    max_files: int = 20_000
    max_total_bytes: int = 2 * 1024**3        # 2 GiB extracted per project
    max_file_bytes: int = 512 * 1024**2       # 512 MiB per member
    max_ratio: float = 200.0                  # compression ratio => archive-bomb guard
    max_depth: int = 3                        # nested container recursion
    tool_timeout_s: int = 300
    max_tool_output: int = 32 * 1024**2


class UnsafeInput(Exception):
    """Raised when untrusted input violates a safety rule."""


def safe_member_path(dest: Path, member: str) -> Path:
    """Resolve an archive member name inside `dest`, rejecting traversal/absolute paths."""
    name = member.replace("\\", "/")
    pp = PurePosixPath(name)
    if pp.is_absolute() or name.startswith("/") or (len(name) > 1 and name[1] == ":"):
        raise UnsafeInput(f"absolute path in archive: {member!r}")
    if any(part == ".." for part in pp.parts):
        raise UnsafeInput(f"path traversal in archive: {member!r}")
    target = (dest / Path(*pp.parts)).resolve() if pp.parts else dest.resolve()
    root = dest.resolve()
    if target != root and root not in target.parents:
        raise UnsafeInput(f"member escapes destination: {member!r}")
    return target


@dataclass
class ToolResult:
    argv: list[str]
    returncode: int | None
    stdout: str
    stderr: str
    duration: float
    timed_out: bool = False
    truncated: bool = False

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out


def run_tool(argv: list[str], timeout: int = 300, max_output: int = 32 * 1024**2,
             cwd: str | os.PathLike | None = None) -> ToolResult:
    """Run an *analysis tool* (never the target) with no shell, a timeout and an output cap."""
    t0 = time.time()
    env = {k: v for k, v in os.environ.items() if not k.upper().endswith(("_API_KEY", "_TOKEN", "_SECRET"))}
    try:
        proc = subprocess.run(argv, capture_output=True, timeout=timeout, cwd=cwd, env=env,
                              stdin=subprocess.DEVNULL, shell=False)
        out, err, trunc = proc.stdout, proc.stderr, False
        if len(out) > max_output:
            out, trunc = out[:max_output], True
        return ToolResult(argv, proc.returncode, out.decode("utf-8", "replace"),
                          err[:65536].decode("utf-8", "replace"), time.time() - t0, False, trunc)
    except subprocess.TimeoutExpired as e:
        return ToolResult(argv, None, (e.stdout or b"")[:65536].decode("utf-8", "replace"),
                          "timeout", time.time() - t0, True)
    except OSError as e:
        return ToolResult(argv, None, "", str(e), time.time() - t0)
