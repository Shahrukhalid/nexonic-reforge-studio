"""Ghidra headless adapter: import -> auto-analysis -> ReForgeExport.java -> JSON findings.

The target is only *analysed* by Ghidra (static); it is never executed. The
temporary Ghidra project is deleted afterwards.
"""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

from ...core.findings import Confidence, Finding, Provenance
from ...core.safety import ToolResult, run_tool

STAGE = "tools"
SCRIPT_DIR = Path(__file__).resolve().parents[1] / "ghidra_scripts"
MAX_DECOMPILED = 25
MAX_CODE_CHARS = 20_000


def build_argv(exe: str, target: Path, proj: Path, out_json: Path, timeout: int) -> list[str]:
    return [exe, str(proj), "reforge", "-import", str(target), "-scriptPath", str(SCRIPT_DIR),
            "-postScript", "ReForgeExport.java", str(out_json), str(MAX_DECOMPILED), "30",
            "-deleteProject", "-analysisTimeoutPerFile", str(max(60, timeout - 120)), "-max-cpu", "2"]


def parse_export(data: dict, rel: str) -> list[Finding]:
    funcs = data.get("functions", [])
    internal = [f for f in funcs if not f.get("external") and not f.get("thunk")]
    out = [Finding(STAGE, "ghidra", "program", "ghidra_program",
                   {k: data.get(k) for k in ("program", "language", "compiler", "image_base", "function_count")},
                   Confidence.CONFIRMED, Provenance.PARSED, "Ghidra auto-analysis", rel)]
    out.append(Finding(STAGE, "ghidra", "functions", "functions",
                       {"count": len(funcs), "internal": len(internal),
                        "items": [{k: f.get(k) for k in ("name", "entry", "size", "signature")}
                                  for f in sorted(internal, key=lambda f: -f.get("size", 0))[:500]]},
                       Confidence.CONFIRMED, Provenance.PARSED, "Ghidra function analysis", rel))
    edges = [[f["name"], c] for f in funcs for c in f.get("calls", [])]
    out.append(Finding(STAGE, "ghidra", "call_graph", "call_graph",
                       {"edges": len(edges), "items": edges[:5000]},
                       Confidence.STRONG, Provenance.INFERRED, "static call references", rel))
    for f in funcs:
        code = f.get("decompiled")
        if code:
            out.append(Finding(STAGE, "ghidra", "decompiled", f["name"],
                               {"entry": f.get("entry"), "signature": f.get("signature"),
                                "code": code[:MAX_CODE_CHARS], "truncated": len(code) > MAX_CODE_CHARS},
                               Confidence.TENTATIVE, Provenance.DECOMPILED,
                               "Ghidra decompiler output - a reconstruction, NOT original source", rel))
    return out


def run_ghidra(exe: str, target: Path, rel: str, timeout: int) -> tuple[str, list[Finding], ToolResult]:
    with tempfile.TemporaryDirectory(prefix="reforge-ghidra-") as tmp:
        proj = Path(tmp) / "proj"
        proj.mkdir()
        out_json = Path(tmp) / "export.json"
        res = run_tool(build_argv(exe, Path(target), proj, out_json, timeout), timeout=timeout,
                       max_output=4 * 1024**2)
        if out_json.is_file() and out_json.stat().st_size:
            try:
                data = json.loads(out_json.read_text(encoding="utf-8", errors="replace"))
                return "ok", parse_export(data, rel), res
            except json.JSONDecodeError as e:
                err = f"export JSON invalid: {e}"
        else:
            err = "Ghidra produced no export (see stderr)"
        tail = (res.stderr or res.stdout)[-3000:]
        return "error", [Finding(STAGE, "ghidra", "tool_error", "ghidra", {"error": err, "rc": res.returncode,
                         "timed_out": res.timed_out, "log_tail": tail}, Confidence.CONFIRMED, subject=rel)], res
