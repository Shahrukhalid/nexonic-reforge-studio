"""Analysis orchestrator: selects and runs stages/tools appropriate to the target.

Never executes the target. Profiles:
  quick    - identification, hashes, layout fingerprint
  standard - + safe extraction, LIEF structure, strings, standard tool adapters
  deep     - + deep adapters (capa, FLOSS, Rizin, GoReSym) within limits
"""
from __future__ import annotations

import logging
import shutil
import time
from pathlib import Path

from ..core.db import Database
from ..core.findings import Confidence, Finding, Provenance
from ..core.safety import Limits, UnsafeInput
from ..core.tasks import TaskContext
from ..tools import adapters
from . import android, binary, disasm, dotnet, extract, fingerprint, identify, msi, pyinstaller, strings

log = logging.getLogger("reforge.orchestrator")

PROFILES = ("quick", "standard", "deep")
NATIVE = {"elf", "pe", "macho", "macho-fat", "appimage"}
ZIPLIKE = {"apk", "aab", "ipa", "jar", "war", "nupkg", "zip", "wheel"}
MAX_EMBEDDED_BINARIES = {"quick": 0, "standard": 12, "deep": 40}
CONTAINER_TOOL_FORMATS = {"apk", "jar", "war"}


class Orchestrator:
    def __init__(self, db: Database, limits: Limits | None = None):
        self.db = db
        self.limits = limits or Limits()

    def analyze(self, pid: int, ctx: TaskContext | None = None) -> dict:
        ctx = ctx or TaskContext("inline")
        proj = self.db.project(pid)
        src = Path(proj["input_path"])
        profile = proj["profile"] if proj["profile"] in PROFILES else "standard"
        work = Path(proj["workdir"])
        if not src.exists():
            raise FileNotFoundError(src)
        self.db.update_project(pid, status="running")
        self.db.clear_findings(pid)
        t0 = time.time()
        try:
            summary = self._run(pid, src, work, profile, ctx)
            self.db.update_project(pid, status="complete")
        except UnsafeInput as e:
            self.db.add_findings(pid, [Finding("safety", "reforge.safety", "safety", "blocked", str(e))])
            self.db.update_project(pid, status="blocked")
            summary = {"blocked": str(e)}
        except Exception:
            self.db.update_project(pid, status="failed")
            raise
        summary["seconds"] = round(time.time() - t0, 2)
        return summary

    # ------------------------------------------------------------------
    def _rec(self, pid, items):
        return self.db.add_findings(pid, items)

    def _run(self, pid: int, src: Path, work: Path, profile: str, ctx: TaskContext) -> dict:
        ctx.progress(2, "Identifying file")
        ident, f = identify.identify_findings(src)
        self._rec(pid, f)
        if src.is_file():
            h = next(x.value for x in f if x.key == "hashes")
            self.db.update_project(pid, sha256=h["sha256"], size=h["size"])
        log.info("project %s: %s (%s)", pid, ident.fmt, ident.description)

        # -------- layout / extraction
        ctx.progress(10, "Inspecting package")
        root: Path | None = None
        names: list[str] = []
        if ident.fmt in ("app-bundle", "ios-app-bundle", "directory"):
            root = src
            names = extract.list_dir(src, self.limits)
            self._rec(pid, extract.bundle_info(src))
        elif ident.fmt in ZIPLIKE or ident.fmt == "asar":
            if profile == "quick":
                if ident.fmt == "asar":
                    hdr, _ = extract.read_asar_header(src)
                    names = [n for n, _ in extract._walk_asar(hdr)]
                else:
                    import zipfile
                    with zipfile.ZipFile(src) as z:
                        names = z.namelist()
            else:
                root = work / "extracted"
                shutil.rmtree(root, ignore_errors=True)
                root.mkdir(parents=True)
                fn = extract.extract_asar if ident.fmt == "asar" else extract.extract_zip
                res = fn(src, root, self.limits)
                names = res.files
                self._rec(pid, [Finding(extract.STAGE, extract.TOOL, "extraction", "summary",
                                        {"files": len(res.files), "skipped_links": res.skipped},
                                        provenance=Provenance.EXTRACTED, subject=src.name)])
        elif ident.fmt in ("dmg", "xar-pkg") and profile != "quick":
            root = work / "extracted"
            shutil.rmtree(root, ignore_errors=True)
            root.mkdir(parents=True)
            res = (extract.extract_dmg if ident.fmt == "dmg" else extract.extract_xar)(src, root, self.limits)
            self._rec(pid, res.findings)
            names = res.files
            if res.root is None:
                root = None
            else:
                for app in root.glob("**/*.app"):
                    if (app / "Contents" / "Info.plist").is_file():
                        self._rec(pid, extract.bundle_info(app))

        if names:
            self._rec(pid, [Finding("inventory", "reforge.extract", "inventory", "files",
                                    {"count": len(names), "sample": sorted(names)[:500]},
                                    provenance=Provenance.EXTRACTED, subject=src.name)])
            self._rec(pid, fingerprint.scan_layout(names, src.name))
            self._rec(pid, _manifest_findings(ident.fmt, root, names))
            if ident.fmt == "apk" and root is not None and (root / "AndroidManifest.xml").is_file():
                self._rec(pid, android.manifest_findings((root / "AndroidManifest.xml").read_bytes()))
        if ident.fmt == "msi":
            ctx.progress(15, "Reading MSI database")
            self._rec(pid, msi.analyze(src))

        # -------- choose analysis subjects
        subjects: list[tuple[Path, str, str]] = []
        if src.is_file() and ident.fmt in NATIVE | {"dex", "wasm", "hermes", "pyc", "java-class", "msi", "unknown"}:
            subjects.append((src, src.name, ident.fmt))
        if root is not None and profile != "quick":
            for rel in names:
                if len(subjects) >= MAX_EMBEDDED_BINARIES[profile] + 1:
                    break
                p = root / rel
                if p.is_file() and p.stat().st_size > 0:
                    sub = identify.identify(p)
                    if sub.fmt in NATIVE | {"dex", "wasm", "hermes"} or (sub.fmt in ZIPLIKE and rel.endswith(".jar")):
                        subjects.append((p, rel, sub.fmt))
            self._rec(pid, [Finding("inventory", "reforge.identify", "inventory", "analysable_subjects",
                                    [{"path": r, "format": fm} for _, r, fm in subjects])])

        # -------- per-subject static analysis
        tools_run = {"ok": 0, "error": 0, "skipped": 0}
        used: dict[str, int] = {}
        for i, (p, rel, fm) in enumerate(subjects):
            base = 20 + int(70 * i / max(1, len(subjects)))
            ctx.progress(base, f"Analysing {rel}")
            if p.is_file():
                self._rec(pid, fingerprint.scan_bytes(p) if profile != "quick" or i == 0 else [])
            quick = profile == "quick"
            if quick and i > 0:
                continue
            if fm in NATIVE and not quick:
                t = time.time()
                try:
                    fs = binary.analyze(p, rel)
                    self._rec(pid, fs)
                    self.db.log_tool_run(pid, "lief", f"lief.parse({rel})", t, "ok")
                except Exception as e:  # noqa: BLE001
                    self.db.log_tool_run(pid, "lief", f"lief.parse({rel})", t, "error", str(e))
                t = time.time()
                try:
                    self._rec(pid, disasm.analyze(p, rel))
                    self.db.log_tool_run(pid, "capstone", f"disasm({rel})", t, "ok")
                except Exception as e:  # noqa: BLE001
                    self.db.log_tool_run(pid, "capstone", f"disasm({rel})", t, "error", str(e))
                if profile == "deep":
                    from ..tools.adapters import angr_adapter
                    if angr_adapter.is_available():
                        t = time.time()
                        status, afs = angr_adapter.run_angr(p, rel)
                        self._rec(pid, afs)
                        self.db.log_tool_run(pid, "angr", f"angr.analyze({rel})", t, status)
                if fm == "pe" and dotnet.is_dotnet(p):
                    self._rec(pid, dotnet.analyze(p, rel))
                    fm = "dotnet"
                pyi = None
                try:
                    pyi = pyinstaller.find_archive(p)
                except UnsafeInput as e:
                    self._rec(pid, [Finding("pyinstaller", "reforge.pyinstaller", "error", "archive_invalid", str(e),
                                            subject=rel)])
                if pyi is not None:
                    self._rec(pid, pyinstaller.findings(pyi, rel))
                    dest = work / "pyinstaller" / f"{i:03d}"
                    shutil.rmtree(dest, ignore_errors=True)
                    files = pyinstaller.extract(pyi, dest, self.limits)
                    self._rec(pid, [Finding("pyinstaller", "reforge.pyinstaller", "extraction", "extracted",
                                            {"files": len(files), "dir": str(dest)}, provenance=Provenance.EXTRACTED,
                                            subject=rel)])
                    for e in pyi.entries:
                        if e.typ == "s" and pyinstaller.is_user_script(e.name):
                            subjects.append((dest / f"{e.name}.pyc", f"{rel}::{e.name}.pyc", "pyc"))
            if fm == "dex" and not quick:
                self._rec(pid, android.dex_findings(p, rel))
            ctx.check()
            if not quick:
                self._rec(pid, strings.analyze(p, rel))
            for a in adapters.applicable(fm, profile):
                ctx.check()
                if a.max_subjects is not None and used.get(a.tool, 0) >= a.max_subjects:
                    continue
                used[a.tool] = used.get(a.tool, 0) + 1
                ctx.progress(base, f"{a.tool}: {rel}")
                t = time.time()
                status, fs, res = adapters.run_adapter(a, p, rel, self.limits.tool_timeout_s)
                tools_run[status] += 1
                self._rec(pid, fs)
                self.db.log_tool_run(pid, a.tool, " ".join(res.argv) if res else "(not installed)", t, status,
                                     res.stderr[-500:] if res and not res.ok else "")

        # container-level engines (decompile the whole package, e.g. JADX on an APK)
        if src.is_file() and ident.fmt in CONTAINER_TOOL_FORMATS:
            for a in adapters.applicable(ident.fmt, profile):
                ctx.check()
                ctx.progress(90, f"{a.tool}: {src.name}")
                t = time.time()
                status, fs, res = adapters.run_adapter(a, src, src.name, self.limits.tool_timeout_s)
                tools_run[status] += 1
                self._rec(pid, fs)
                self.db.log_tool_run(pid, a.tool, " ".join(res.argv) if res else "(not installed)", t, status,
                                     res.stderr[-500:] if res and not res.ok else "")

        ctx.progress(95, "Summarising")
        self._rec(pid, [_feasibility(self.db.findings(pid), ident.fmt)])
        ctx.progress(100, "Done")
        return {"format": ident.fmt, "subjects": len(subjects), "files": len(names), "tools": tools_run}


def _manifest_findings(fmt: str, root: Path | None, names: list[str]) -> list[Finding]:
    out: list[Finding] = []
    if root is None:
        return out
    if fmt in ("jar", "war") and (root / "META-INF/MANIFEST.MF").is_file():
        kv = {}
        for line in (root / "META-INF/MANIFEST.MF").read_text(errors="replace").splitlines():
            if ": " in line:
                k, v = line.split(": ", 1)
                kv[k.strip()] = v.strip()
        out.append(Finding("extract", "reforge.extract", "metadata", "jar_manifest", kv, subject="META-INF/MANIFEST.MF"))
    if fmt == "asar" and (root / "package.json").is_file():
        import json
        try:
            pkg = json.loads((root / "package.json").read_text(errors="replace"))
            keep = {k: pkg[k] for k in ("name", "productName", "version", "main", "description", "dependencies",
                                        "devDependencies") if k in pkg}
            out.append(Finding("extract", "reforge.extract", "metadata", "package_json", keep, subject="package.json"))
        except ValueError:
            pass
    if fmt == "apk":
        out.append(Finding("extract", "reforge.extract", "metadata", "apk_contents",
                           {"dex": [n for n in names if n.endswith(".dex")],
                            "native_abis": sorted({n.split("/")[1] for n in names if n.startswith("lib/") and n.count("/") >= 2})},
                           Confidence.CONFIRMED, subject="APK"))
    if fmt == "aab":
        out.append(Finding("extract", "reforge.extract", "limitation", "aab_manifest",
                           "AAB manifests are protobuf (not binary XML); decoding not implemented yet",
                           Confidence.CONFIRMED))
    return out


def _feasibility(rows: list[dict], fmt: str) -> Finding:
    techs = sorted({r["key"] for r in rows if r["kind"] == "technology"})
    net = sum(len(r["value"]) for r in rows if r["kind"] == "network" and isinstance(r["value"], list))
    notes = []
    if any("Electron" in t for t in techs) or fmt == "asar":
        notes.append("JavaScript sources are typically recoverable from ASAR (as packaged, possibly minified).")
    if fmt in ("jar", "apk", "dex") or "Java" in techs:
        notes.append("JVM/DEX bytecode decompiles well; output is decompiled representation, not original source.")
    if any(t.startswith("Unity IL2CPP") for t in techs):
        notes.append("IL2CPP: C# metadata recoverable; method bodies are native code.")
    if fmt in NATIVE and not any(t in techs for t in ("Electron", "PyInstaller")):
        notes.append("Native code: behaviour must be inferred from disassembly/decompilation; expect manual effort.")
    if net:
        notes.append(f"{net} network indicators found; server-side logic is NOT recoverable from a client.")
    return Finding("report", "reforge.orchestrator", "feasibility", "reconstruction_feasibility",
                   {"technologies": techs, "notes": notes, "status": "preliminary"}, Confidence.TENTATIVE,
                   Provenance.INFERRED, "heuristic summary of findings above")
