"""Headless CLI: `reforge-cli analyze FILE [--profile standard] [--report out.md]`, `reforge-cli tools`."""
from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

from .analysis import report
from .analysis.orchestrator import PROFILES, Orchestrator
from .core.db import Database
from .core.tasks import TaskContext
from .tools import registry


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="reforge-cli")
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("analyze")
    a.add_argument("target")
    a.add_argument("--profile", choices=PROFILES, default="standard")
    a.add_argument("--report")
    t = sub.add_parser("tools")
    t.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    if args.cmd == "tools":
        sts = registry.all_status()
        if args.json:
            print(json.dumps([{"id": s.entry["id"], "name": s.entry["name"], "status": s.status,
                               "version": s.version, "location": s.location} for s in sts], indent=1))
        else:
            for s in sts:
                print(f"{s.entry['id']:>2} {s.entry['name'][:32]:<32} {s.status}")
            print(registry.summary())
        return 0

    target = Path(args.target).resolve()
    db = Database()
    pid = db.create_project(target.name, str(target), args.profile)
    ctx = TaskContext("cli", on_progress=lambda p, m: print(f"[{p:3d}%] {m}", file=sys.stderr))
    summary = Orchestrator(db).analyze(pid, ctx)
    print(json.dumps({"project_id": pid, **summary}, indent=1))
    if args.report:
        print("report:", report.export(db, pid, Path(args.report)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
