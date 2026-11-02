"""Headless CLI: `reforge-cli analyze FILE [--profile standard] [--report out.md]`, `reforge-cli tools`."""
from __future__ import annotations

import argparse
import json
import logging
import os
import subprocess
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
    sub.add_parser("doctor", help="check JDK, tool packs and external engines on this machine")
    tp = sub.add_parser("toolpack", help="install/list verified tool packs")
    tp.add_argument("action", choices=["list", "install", "uninstall", "build-natives"])
    tp.add_argument("pack", nargs="?")
    args = ap.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    if args.cmd == "doctor":
        from .tools import jdk, toolpacks
        from .tools.adapters.ghidra import DEFAULT_JAVA_MIN, required_java
        gx = registry.find_exe("Ghidra")
        need = required_java(gx) if gx else DEFAULT_JAVA_MIN
        j = jdk.find_jdk(need)
        print(f"JDK {need}+        : {'OK  ' + str(j[1]) + '  ' + str(j[0]) if j else f'MISSING - Ghidra needs JDK {need}+ (macOS: brew install openjdk)'}")
        if gx:
            from .tools.adapters.ghidra import decompiler_native, native_platform
            d = decompiler_native(gx)
            print(f"Ghidra decomp. : {'OK  ' + str(d) if d.is_file() else 'MISSING for ' + native_platform() + ' - run: reforge-cli toolpack build-natives ghidra'}")
        for pid, spec in toolpacks.packs().items():
            print(f"pack {pid:<9} : {'installed' if toolpacks.is_installed(pid) else 'not installed'} ({spec['version']})")
        for s in registry.all_status():
            if s.available:
                print(f"tool           : {s.entry['name']:<28} {s.version or s.location or ''}")
        return 0

    if args.cmd == "toolpack":
        from .tools import toolpacks
        if args.action == "list":
            for pid, spec in toolpacks.packs().items():
                state = "installed" if toolpacks.is_installed(pid) else "not installed"
                print(f"{pid:<10} {spec['name']} {spec['version']} ({spec['license']}, ~{spec['size_hint_mb']} MB) - {state}")
            return 0
        if not args.pack:
            ap.error("pack id required")
        if args.action == "build-natives":
            if args.pack != "ghidra":
                ap.error("build-natives is only needed for ghidra")
            from .tools import jdk
            from .tools.adapters.ghidra import decompiler_native, ghidra_root, required_java
            gx = registry.find_exe("Ghidra")
            if not gx:
                ap.error("Ghidra is not installed: reforge-cli toolpack install ghidra")
            root = ghidra_root(gx)
            script = root / "support" / ("buildNatives.bat" if os.name == "nt" else "buildNatives")
            if not script.is_file():
                print(f"not found: {script}")
                return 1
            found = jdk.find_jdk(required_java(gx))
            if not found:
                print("JDK missing - see: reforge-cli doctor")
                return 1
            print(f"Building Ghidra native components in {root} (Ghidra's own script; takes a few minutes)...")
            env = {**os.environ, **jdk.env_for(found[0])}
            rc = subprocess.call([str(script)], cwd=str(root / "support"), env=env)
            ok = decompiler_native(gx).is_file()
            print("decompiler:", "OK " + str(decompiler_native(gx)) if ok else "still missing (see output above)")
            return 0 if ok else (rc or 1)
        if args.action == "install":
            last = [-1]

            def prog(done, total):
                pct = int(done * 100 / total) if total else 0
                if pct != last[0] and pct % 5 == 0:
                    last[0] = pct
                    print(f"  {pct:3d}%  {done // 2**20} MB", file=sys.stderr)
            print("installed:", toolpacks.install(args.pack, prog))
        else:
            toolpacks.uninstall(args.pack)
        return 0

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
