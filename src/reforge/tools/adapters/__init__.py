"""CLI adapters for external analysis tools.

Each adapter: declares which formats it applies to, runs the tool with an
argument list (no shell) under timeout, and converts output to Findings.
Adapters are skipped (and recorded as such) when the tool is not installed.
"""
from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from ...core.findings import Confidence, Finding, Provenance
from ...core.safety import ToolResult, run_tool
from .. import registry

STAGE = "tools"


@dataclass
class Adapter:
    tool: str                                   # registry name
    formats: set[str]                           # identify() formats it applies to
    profiles: set[str]                          # quick / standard / deep
    argv: Callable[[str, Path], list[str]]      # (exe, target) -> argv
    parse: Callable[[ToolResult, str], list[Finding]] | None = None
    timeout: int = 300
    max_subjects: int | None = None             # cap per analysis (expensive engines)
    runner: Callable | None = None              # (exe, target, rel, timeout) -> (status, findings, ToolResult)


def _json_or_text(res: ToolResult, tool: str, key: str, rel: str) -> list[Finding]:
    if not res.ok:
        return [Finding(STAGE, tool, "tool_error", key, {"rc": res.returncode, "stderr": res.stderr[-2000:],
                        "timed_out": res.timed_out}, Confidence.CONFIRMED, subject=rel)]
    try:
        val = json.loads(res.stdout)
    except json.JSONDecodeError:
        val = res.stdout[:200_000]
    return [Finding(STAGE, tool, "tool_output", key, val, Confidence.CONFIRMED, Provenance.PARSED,
                    f"{tool} output" + (" (truncated)" if res.truncated else ""), rel)]


def _capa(res: ToolResult, rel: str) -> list[Finding]:
    out = _json_or_text(res, "capa", "capabilities", rel)
    v = out[0].value
    if isinstance(v, dict) and "rules" in v:
        caps = sorted({r.get("meta", {}).get("name", k) for k, r in v["rules"].items()})
        out = [Finding(STAGE, "capa", "capabilities", "capa_rules", caps, Confidence.STRONG, Provenance.INFERRED,
                       "capa rule matches (static)", rel)]
    return out


EXECUTABLES = {"elf", "pe", "macho", "macho-fat", "appimage"}

ADAPTERS: list[Adapter] = [
    Adapter("Detect It Easy", EXECUTABLES | {"apk", "jar", "dex", "msi", "zip"}, {"quick", "standard", "deep"},
            lambda exe, t: [exe, "-j", str(t)], lambda r, rel: _json_or_text(r, "diec", "die_scan", rel), 120),
    Adapter("radare2", EXECUTABLES | {"dex", "wasm"}, {"standard", "deep"},
            lambda exe, t: [exe, "-Ij", str(t)] if exe.endswith(("rabin2", "rabin2.exe")) else
            [exe, "-q", "-c", "ij", str(t)], lambda r, rel: _json_or_text(r, "radare2", "rabin2_info", rel), 120),
    Adapter("Rizin", EXECUTABLES | {"dex", "wasm"}, {"deep"},
            lambda exe, t: [exe, "-Ij", str(t)], lambda r, rel: _json_or_text(r, "rizin", "rz_bin_info", rel), 120),
    Adapter("WABT", {"wasm"}, {"standard", "deep"},
            lambda exe, t: [exe, "-x", str(t)] if "objdump" in exe else [exe, str(t)],
            lambda r, rel: _json_or_text(r, "wabt", "wasm_details", rel), 120),
    Adapter("capa", {"elf", "pe", "macho"}, {"deep"},
            lambda exe, t: [exe, "-j", str(t)], _capa, 900),
    Adapter("FLOSS", {"pe"}, {"deep"},
            lambda exe, t: [exe, "-j", "--quiet", str(t)], lambda r, rel: _json_or_text(r, "floss", "floss", rel), 900),
    Adapter("GoReSym", {"elf", "pe", "macho"}, {"deep"},
            lambda exe, t: [exe, "-t", "-p", str(t)], lambda r, rel: _json_or_text(r, "goresym", "go_symbols", rel), 300),
]


from .ghidra import run_ghidra  # noqa: E402

ADAPTERS.append(Adapter("Ghidra", {"elf", "pe", "macho", "macho-fat"}, {"deep"}, argv=lambda exe, t: [], timeout=1800,
                        max_subjects=1, runner=run_ghidra))


def applicable(fmt: str, profile: str) -> list[Adapter]:
    return [a for a in ADAPTERS if fmt in a.formats and profile in a.profiles]


def run_adapter(a: Adapter, target: Path, rel: str, timeout: int | None = None
                ) -> tuple[str, list[Finding], ToolResult | None]:
    exe = registry.find_exe(a.tool)
    if not exe:
        return "skipped", [], None
    t = max(a.timeout, timeout or 0)
    if a.runner:
        return a.runner(exe, target, rel, t)
    res = run_tool(a.argv(exe, target), timeout=t)
    return ("ok" if res.ok else "error"), a.parse(res, rel), res
