"""Builds project-aware context and system prompt for the AI Assistant."""
from __future__ import annotations

import json
from typing import Any

SYSTEM_PROMPT = """You are the Nexonic ReForge Studio AI Assistant, an expert reverse-engineering, binary analysis, and clean-room software architecture specialist.

Your mission is to help the user:
1. Understand binary analysis findings, security indicators, and file formats.
2. Interpret decompiled code and disassembly accurately.
3. Formulate independent, clean-room functional specifications and architecture designs based on authorized analysis.
4. Assist with generating original implementation code, unit tests, and debugging.

Key Rules:
- Decompiled code is a reconstructed representation, NEVER original proprietary source code.
- Never hallucinate or fabricate findings. Base explanations strictly on the provided analysis findings.
- Explicitly distinguish confirmed extracted findings from inferred behavior.
- Support clean-room development: design independent implementations based on functional requirements without infringing proprietary code.
"""


def build_project_context(db: Any, pid: int, max_findings: int = 50) -> str:
    """Compile project findings and metadata into an AI context block."""
    p = db.project(pid)
    if not p:
        return "No project loaded."

    rows = db.findings(pid)
    techs = sorted({r["key"] for r in rows if r["kind"] == "technology"})

    summary = {
        "project_id": pid,
        "name": p.get("name"),
        "format": p.get("format"),
        "sha256": p.get("sha256"),
        "profile": p.get("profile"),
        "status": p.get("status"),
        "technologies": techs,
    }

    # Extract key findings
    endpoints = []
    libraries = []
    code_samples = []

    for r in rows:
        key = r.get("key", "")
        kind = r.get("kind", "")
        val = r.get("value")

        if kind == "network" and isinstance(val, list):
            endpoints.extend(val[:20])
        elif key == "libraries" and isinstance(val, list):
            libraries.extend(val[:30])
        elif kind == "decompiled" and isinstance(val, dict) and "code" in val:
            code_samples.append({
                "subject": r.get("subject", key),
                "code_snippet": val["code"][:1500]
            })

    lines = [
        f"--- PROJECT ANALYSIS CONTEXT (Project #{pid}: {p.get('name')}) ---",
        json.dumps(summary, indent=2),
    ]

    if libraries:
        lines.append("\n[Imported Libraries / Dependencies]:")
        lines.append(", ".join(sorted(set(libraries))[:25]))

    if endpoints:
        lines.append("\n[Network Endpoints / URLs]:")
        lines.append("\n".join(f"- {u}" for u in sorted(set(endpoints))[:20]))

    if code_samples:
        lines.append(f"\n[Decompiled Code Samples ({len(code_samples[:3])} files)]:")
        for cs in code_samples[:3]:
            lines.append(f"\n// File: {cs['subject']} (Decompiled representation)")
            lines.append(cs["code_snippet"])

    lines.append("\n--- END OF CONTEXT ---")
    return "\n".join(lines)
