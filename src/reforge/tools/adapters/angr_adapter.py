"""angr adapter: binary analysis and CFG recovery via Python angr library."""
from __future__ import annotations

import logging
from pathlib import Path

from ...core.findings import Confidence, Finding, Provenance

log = logging.getLogger("reforge.angr")
STAGE = "tools"


def is_available() -> bool:
    try:
        import angr  # noqa: F401
        return True
    except ImportError:
        return False


def run_angr(target: Path, rel: str, max_functions: int = 50) -> tuple[str, list[Finding]]:
    """Perform static binary analysis and basic CFG recovery using angr without execution."""
    try:
        import angr
    except ImportError:
        return "skipped", []

    try:
        proj = angr.Project(str(target), auto_load_libs=False)
        arch = str(proj.arch)
        entry = hex(proj.entry)

        # Fast CFG recovery (static only)
        cfg = proj.analyses.CFGFast()
        funcs = []
        for addr, func in sorted(cfg.kb.functions.items()):
            if len(funcs) >= max_functions:
                break
            funcs.append({
                "addr": hex(addr),
                "name": func.name,
                "size": func.size,
                "block_count": len(func.block_addrs),
                "has_return": func.has_return,
                "is_syscall": func.is_syscall,
            })

        val = {
            "arch": arch,
            "entry": entry,
            "total_functions": len(cfg.kb.functions),
            "sample_functions": funcs,
        }
        findings = [
            Finding(STAGE, "angr", "binary_cfg", "angr_cfg_summary", val,
                    Confidence.CONFIRMED, Provenance.PARSED, "angr static CFG analysis", rel)
        ]
        return "ok", findings
    except Exception as e:
        log.warning("angr analysis failed for %s: %s", rel, e)
        return "error", [
            Finding(STAGE, "angr", "tool_error", "angr_failed",
                    {"error": str(e)}, Confidence.CONFIRMED, subject=rel)
        ]
