"""Ghidra headless adapter: import -> auto-analysis -> ReForgeExport.java -> JSON findings.

The target is only *analysed* by Ghidra (static); it is never executed. The
temporary Ghidra project is deleted afterwards.
"""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

import lief

from ...core.findings import Confidence, Finding, Provenance
from ...core.safety import ToolResult, run_tool
from .. import jdk

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


PREFERRED_SLICES = ("ARM64", "X86_64")


def thin_macho(target: Path, out_dir: Path) -> tuple[Path, str] | None:
    """Write one slice of a universal Mach-O as a thin binary (preferring arm64). None if not fat."""
    fat = lief.MachO.parse(str(target))
    if fat is None or fat.size < 2:
        return None
    slices = list(fat)
    names = [str(b.header.cpu_type).split(".")[-1] for b in slices]
    idx = next((names.index(p) for p in PREFERRED_SLICES if p in names), 0)
    out = out_dir / f"{target.name}.{names[idx].lower()}"
    slices[idx].write(str(out))
    return out, names[idx]


def _err(rel: str, msg: str, res: ToolResult | None = None) -> tuple[str, list[Finding], ToolResult | None]:
    v = {"error": msg}
    if res is not None:
        v |= {"rc": res.returncode, "timed_out": res.timed_out, "log_tail": (res.stderr or res.stdout)[-3000:]}
    return "error", [Finding(STAGE, "ghidra", "tool_error", "ghidra", v, Confidence.CONFIRMED, subject=rel)], res


DEFAULT_JAVA_MIN = 25   # Ghidra 12.x


def required_java(exe: str) -> int:
    """Minimum JDK major version declared by this Ghidra install (Ghidra/application.properties)."""
    props = Path(exe).resolve().parent.parent / "Ghidra" / "application.properties"
    try:
        for line in props.read_text(errors="replace").splitlines():
            if line.strip().startswith("application.java.min="):
                return int(line.split("=", 1)[1].strip())
    except (OSError, ValueError):
        pass
    return DEFAULT_JAVA_MIN


def run_ghidra(exe: str, target: Path, rel: str, timeout: int) -> tuple[str, list[Finding], ToolResult | None]:
    need = required_java(exe)
    found = jdk.find_jdk(need)
    if found is None:
        return _err(rel, f"This Ghidra needs JDK {need} or newer; none found (checked JAVA_HOME, java_home, "
                         "Homebrew, standard JDK folders, PATH)")
    home, major = found
    with tempfile.TemporaryDirectory(prefix="reforge-ghidra-") as tmp:
        target = Path(target)
        notes = {"jdk": f"{major} ({home})"}
        thin = thin_macho(target, Path(tmp)) if lief.is_macho(str(target)) else None
        if thin:
            target, notes["slice"] = thin
        proj = Path(tmp) / "proj"
        proj.mkdir()
        out_json = Path(tmp) / "export.json"
        res = run_tool(build_argv(exe, target, proj, out_json, timeout), timeout=timeout,
                       max_output=4 * 1024**2, extra_env=jdk.env_for(home))
        if out_json.is_file() and out_json.stat().st_size:
            try:
                data = json.loads(out_json.read_text(encoding="utf-8", errors="replace"))
            except json.JSONDecodeError as e:
                return _err(rel, f"export JSON invalid: {e}", res)
            fs = parse_export(data, rel)
            fs[0].value |= notes
            return "ok", fs, res
        return _err(rel, "Ghidra produced no export (see log_tail)", res)
