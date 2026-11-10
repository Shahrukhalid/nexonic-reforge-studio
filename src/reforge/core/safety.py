"""Untrusted-input safety primitives: limits, path containment, subprocess runner.

Nothing in this module ever executes the *target* application. `run_tool` only
runs analysis tools from the registry, with an argument list (never a shell),
a timeout and an output cap.
"""
from __future__ import annotations

import os
import subprocess
import threading
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
             cwd: str | os.PathLike | None = None, extra_env: dict[str, str] | None = None) -> ToolResult:
    """Run an *analysis tool* (never the target) with no shell, a timeout and an output cap
    enforced continuously during execution to prevent resource exhaustion."""
    t0 = time.time()
    env = {k: v for k, v in os.environ.items() if not k.upper().endswith(("_API_KEY", "_TOKEN", "_SECRET"))}
    env.update(extra_env or {})
    try:
        proc = subprocess.Popen(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.DEVNULL,
            cwd=cwd,
            env=env,
            shell=False,
        )
    except OSError as e:
        return ToolResult(argv, None, "", str(e), time.time() - t0)

    out_chunks: list[bytes] = []
    err_chunks: list[bytes] = []
    out_len = 0
    err_len = 0
    max_err = 65536
    truncated = False
    timed_out = False

    def reader(stream, chunks, limit, is_out):
        nonlocal out_len, err_len, truncated
        try:
            while True:
                chunk = stream.read(8192)
                if not chunk:
                    break
                if is_out:
                    if out_len + len(chunk) > limit:
                        allowed = max(0, limit - out_len)
                        if allowed:
                            chunks.append(chunk[:allowed])
                            out_len += allowed
                        truncated = True
                        try:
                            proc.terminate()
                        except Exception:
                            pass
                        break
                    chunks.append(chunk)
                    out_len += len(chunk)
                else:
                    if err_len + len(chunk) > limit:
                        allowed = max(0, limit - err_len)
                        if allowed:
                            chunks.append(chunk[:allowed])
                            err_len += allowed
                        break
                    chunks.append(chunk)
                    err_len += len(chunk)
        finally:
            stream.close()

    t_out = threading.Thread(target=reader, args=(proc.stdout, out_chunks, max_output, True))
    t_err = threading.Thread(target=reader, args=(proc.stderr, err_chunks, max_err, False))
    t_out.daemon = True
    t_err.daemon = True
    t_out.start()
    t_err.start()

    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        try:
            proc.kill()
        except Exception:
            pass
        try:
            proc.wait(timeout=2.0)
        except Exception:
            pass

    t_out.join(timeout=1.0)
    t_err.join(timeout=1.0)

    out_bytes = b"".join(out_chunks)
    err_bytes = b"".join(err_chunks)
    err_str = "timeout" if timed_out else err_bytes.decode("utf-8", "replace")

    return ToolResult(
        argv,
        proc.returncode if not timed_out else None,
        out_bytes.decode("utf-8", "replace"),
        err_str,
        time.time() - t0,
        timed_out,
        truncated,
    )
