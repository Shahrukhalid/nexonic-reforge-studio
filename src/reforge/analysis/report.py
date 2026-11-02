"""Report export (Markdown + JSON) from stored findings."""
from __future__ import annotations

import json
from pathlib import Path

from ..core.db import Database

ORDER = ["identify", "extract", "inventory", "fingerprint", "binary", "strings", "tools", "safety", "report"]


def to_json(db: Database, pid: int) -> dict:
    return {"project": db.project(pid), "findings": db.findings(pid), "tool_runs": db.tool_runs(pid),
            "disclaimer": "Findings are labelled by confidence and provenance. Decompiled or inferred "
                          "content is not original source code."}


def to_markdown(db: Database, pid: int) -> str:
    p = db.project(pid)
    rows = db.findings(pid)
    lines = [f"# Analysis report: {p['name']}", "", f"- Input: `{p['input_path']}`",
             f"- SHA-256: `{p['sha256']}`", f"- Size: {p['size']} bytes", f"- Profile: {p['profile']}",
             f"- Status: {p['status']}", "",
             "> Confidence levels: confirmed / strongly_inferred / tentative / unknown. "
             "Inferred items are heuristics, not facts.", ""]
    for stage in ORDER + sorted({r["stage"] for r in rows} - set(ORDER)):
        st = [r for r in rows if r["stage"] == stage]
        if not st:
            continue
        lines += [f"## {stage}", ""]
        for r in st:
            v = r["value"]
            txt = json.dumps(v, default=str)
            if len(txt) > 600:
                txt = txt[:600] + " ..."
            subj = f" ({r['subject']})" if r["subject"] else ""
            lines.append(f"- **{r['key']}**{subj} [{r['confidence']}, {r['provenance']}, {r['tool']}]: `{txt}`")
        lines.append("")
    runs = db.tool_runs(pid)
    if runs:
        lines += ["## Tool executions", "", "| Tool | Status | Command |", "|---|---|---|"]
        lines += [f"| {r['tool']} | {r['status']} | `{r['command'][:120]}` |" for r in runs]
    return "\n".join(lines) + "\n"


def export(db: Database, pid: int, dest: Path) -> Path:
    dest = Path(dest)
    if dest.suffix == ".json":
        dest.write_text(json.dumps(to_json(db, pid), indent=1, default=str))
    else:
        dest.write_text(to_markdown(db, pid))
    return dest
