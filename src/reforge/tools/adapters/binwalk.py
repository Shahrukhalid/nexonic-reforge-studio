"""Binwalk adapter: signature analysis for embedded files, compressed chunks, and headers."""
from __future__ import annotations

import re
from pathlib import Path

from ...core.findings import Confidence, Finding, Provenance
from ...core.safety import ToolResult, run_tool

STAGE = "tools"


def parse_binwalk_output(text: str) -> list[dict]:
    """Parse standard binwalk output table: DECIMAL HEXADECIMAL DESCRIPTION."""
    entries = []
    lines = text.strip().splitlines()
    for line in lines:
        line = line.strip()
        if not line or line.startswith(("-", "DECIMAL", "WARNING")):
            continue
        m = re.match(r"^(\d+)\s+(0x[0-9a-fA-F]+)\s+(.+)$", line)
        if m:
            dec_off, hex_off, desc = m.groups()
            entries.append({"offset_dec": int(dec_off), "offset_hex": hex_off, "description": desc.strip()})
    return entries


def run_binwalk(exe: str, target: Path, rel: str, timeout: int) -> tuple[str, list[Finding], ToolResult | None]:
    # Run binwalk signature scan
    res = run_tool([exe, "-B", str(target)], timeout=timeout)
    if not res.ok and not res.stdout:
        return "error", [Finding(STAGE, "Binwalk", "tool_error", "binwalk_failed",
                                 {"rc": res.returncode, "error": res.stderr[-2000:]}, Confidence.CONFIRMED, subject=rel)], res

    signatures = parse_binwalk_output(res.stdout)
    findings = [
        Finding(STAGE, "Binwalk", "embedded_signatures", "binwalk_signatures",
                {"count": len(signatures), "signatures": signatures[:100]},
                Confidence.CONFIRMED if signatures else Confidence.TENTATIVE,
                Provenance.PARSED, "Binwalk embedded signatures", rel)
    ]
    return "ok", findings, res
