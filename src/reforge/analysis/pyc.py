"""Python bytecode (.pyc) analyzer.

Extracts code objects, functions, arguments, bytecode disassembly, and string constants
directly from compiled .pyc files using standard Python marshal and dis engines.
"""
from __future__ import annotations

import dis
import marshal
from pathlib import Path
from typing import Any

from ..core.findings import Confidence, Finding, Provenance

STAGE = "bytecode"
TOOL = "reforge.pyc"


def _walk_code_objects(co: Any, functions: list[dict[str, Any]], strings: list[str]) -> None:
    """Recursively collect nested code objects (functions, lambdas, generators) and strings."""
    for c in getattr(co, "co_consts", ()):
        if hasattr(c, "co_name"):
            insns: list[str] = []
            try:
                for insn in dis.get_instructions(c):
                    insns.append(f"{insn.offset:04d}: {insn.opname:<20} {insn.argrepr}")
            except Exception:
                pass

            functions.append({
                "name": c.co_name,
                "argcount": getattr(c, "co_argcount", 0),
                "varnames": list(getattr(c, "co_varnames", ())),
                "filename": getattr(c, "co_filename", ""),
                "firstlineno": getattr(c, "co_firstlineno", 0),
                "instructions": insns[:100],
            })
            _walk_code_objects(c, functions, strings)
        elif isinstance(c, str) and len(c.strip()) > 1:
            strings.append(c)


def analyze(path: Path, rel: str = "") -> list[Finding]:
    """Analyze a compiled .pyc file and generate structured findings."""
    rel = rel or Path(path).name
    try:
        data = path.read_bytes()
    except Exception as e:
        return [Finding(STAGE, TOOL, "error", "pyc_read_failed", str(e), subject=rel)]

    # Standard pyc header: 16 bytes for Python 3.7+ (magic: 4, bitfield: 4, timestamp/hash: 4, size: 4)
    # Older pyc used 8 or 12 bytes
    co: Any = None
    for header_offset in (16, 12, 8):
        if len(data) > header_offset:
            try:
                co = marshal.loads(data[header_offset:])
                if hasattr(co, "co_name"):
                    break
            except Exception:
                continue

    if co is None or not hasattr(co, "co_name"):
        return [Finding(STAGE, TOOL, "error", "pyc_unmarshal_failed", "Could not unmarshal code object from .pyc", subject=rel)]

    functions: list[dict[str, Any]] = []
    strings: list[str] = []

    # Root module functions and strings
    _walk_code_objects(co, functions, strings)

    # Root code names also contain module-level calls and imports
    for name in getattr(co, "co_names", ()):
        if isinstance(name, str) and name not in strings:
            strings.append(name)

    findings: list[Finding] = []

    # Function findings
    func_names = [f["name"] for f in functions if not f["name"].startswith("<")]
    if func_names:
        findings.append(
            Finding(
                stage="functions",
                tool=TOOL,
                kind="function",
                key="recovered_functions",
                value=func_names,
                confidence=Confidence.CONFIRMED,
                provenance=Provenance.PARSED,
                evidence=f"Extracted {len(func_names)} function code objects from bytecode",
                subject=rel,
            )
        )

    for fn in functions:
        if not fn["name"].startswith("<"):
            findings.append(
                Finding(
                    stage="decompiled",
                    tool=TOOL,
                    kind="decompiled_functions",
                    key=f"function:{fn['name']}",
                    value=fn,
                    confidence=Confidence.CONFIRMED,
                    provenance=Provenance.PARSED,
                    evidence=f"Bytecode disassembly for {fn['name']}",
                    subject=rel,
                )
            )

    # Constant string findings
    for s in set(strings):
        findings.append(
            Finding(
                stage="strings",
                tool=TOOL,
                kind="string",
                key="string",
                value=s,
                confidence=Confidence.CONFIRMED,
                provenance=Provenance.EXTRACTED,
                evidence="co_consts string literal",
                subject=rel,
            )
        )

    return findings
