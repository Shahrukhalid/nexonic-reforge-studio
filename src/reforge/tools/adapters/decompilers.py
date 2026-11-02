"""Decompiler adapters writing to a temp directory: JADX (APK/DEX/JAR) and ILSpy (ilspycmd, .NET).

Output is a decompiled representation (never original source). Only a bounded sample
of files is stored as findings; the full tree is kept under the project workdir.
"""
from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

from ...core.findings import Confidence, Finding, Provenance
from ...core.safety import ToolResult, run_tool

STAGE = "tools"
SAMPLE_FILES = 12
MAX_CODE = 20_000


def _collect(root: Path, suffix: str, rel: str, tool: str, keep_dir: Path | None) -> list[Finding]:
    files = sorted(p for p in root.rglob(f"*{suffix}") if p.is_file())
    if keep_dir is not None:
        shutil.rmtree(keep_dir, ignore_errors=True)
        shutil.copytree(root, keep_dir)
    out = [Finding(STAGE, tool, "decompiled_tree", f"{tool}_output",
                   {"files": len(files), "sample": [f.relative_to(root).as_posix() for f in files[:500]],
                    "saved_to": str(keep_dir) if keep_dir else None},
                   Confidence.CONFIRMED, Provenance.DECOMPILED, f"{tool} decompiler output", rel)]
    # largest files first: usually the most informative
    for f in sorted(files, key=lambda p: -p.stat().st_size)[:SAMPLE_FILES]:
        code = f.read_text(errors="replace")
        out.append(Finding(STAGE, tool, "decompiled", f.relative_to(root).as_posix(),
                           {"code": code[:MAX_CODE], "truncated": len(code) > MAX_CODE},
                           Confidence.TENTATIVE, Provenance.DECOMPILED,
                           f"{tool} output - a reconstruction, NOT original source", rel))
    return out


def _error(tool: str, rel: str, res: ToolResult) -> list[Finding]:
    return [Finding(STAGE, tool, "tool_error", tool, {"rc": res.returncode, "timed_out": res.timed_out,
                    "log_tail": (res.stderr or res.stdout)[-3000:]}, Confidence.CONFIRMED, subject=rel)]


def run_jadx(exe: str, target: Path, rel: str, timeout: int, keep_dir: Path | None = None):
    with tempfile.TemporaryDirectory(prefix="reforge-jadx-") as tmp:
        out = Path(tmp) / "out"
        res = run_tool([exe, "--no-res", "--threads-count", "2", "--quiet", "-d", str(out), str(target)],
                       timeout=timeout)
        src = out / "sources"
        if src.is_dir() and any(src.rglob("*.java")):
            # jadx exits non-zero when some methods fail but still produces usable output
            return "ok", _collect(src, ".java", rel, "jadx", keep_dir), res
        return "error", _error("jadx", rel, res), res


def run_ilspy(exe: str, target: Path, rel: str, timeout: int, keep_dir: Path | None = None):
    with tempfile.TemporaryDirectory(prefix="reforge-ilspy-") as tmp:
        out = Path(tmp) / "out"
        res = run_tool([exe, "-p", "-o", str(out), str(target)], timeout=timeout)
        if out.is_dir() and any(out.rglob("*.cs")):
            return "ok", _collect(out, ".cs", rel, "ilspy", keep_dir), res
        return "error", _error("ilspy", rel, res), res
