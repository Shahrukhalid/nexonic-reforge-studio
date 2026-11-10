"""Apktool adapter: decodes Android resources, manifest, and structure into a project workdir."""
from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

from ...core.findings import Confidence, Finding, Provenance
from ...core.safety import ToolResult, run_tool

STAGE = "tools"
MAX_FILES = 500


def run_apktool(exe: str, target: Path, rel: str, timeout: int, keep_dir: Path | None = None) -> tuple[str, list[Finding], ToolResult | None]:
    with tempfile.TemporaryDirectory(prefix="reforge-apktool-") as tmp:
        out = Path(tmp) / "decoded"
        # -s: do not decompile sources (DEX) if JADX handles it, or decode resources & manifest
        # -f: force overwrite existing
        res = run_tool([exe, "d", "-f", "-s", "-o", str(out), str(target)], timeout=timeout)
        if not out.is_dir():
            err_msg = (res.stderr or res.stdout)[-2000:]
            return "error", [Finding(STAGE, "Apktool", "tool_error", "apktool_failure",
                                     {"rc": res.returncode, "error": err_msg}, Confidence.CONFIRMED, subject=rel)], res

        if keep_dir is not None:
            shutil.rmtree(keep_dir, ignore_errors=True)
            shutil.copytree(out, keep_dir)

        files = [p.relative_to(out).as_posix() for p in out.rglob("*") if p.is_file()]
        manifest_text = ""
        manifest_file = out / "AndroidManifest.xml"
        if manifest_file.is_file():
            manifest_text = manifest_file.read_text(errors="replace")[:100_000]

        findings = [
            Finding(STAGE, "Apktool", "resources", "apktool_decoded",
                    {"files": len(files), "sample": sorted(files)[:MAX_FILES],
                     "saved_to": str(keep_dir) if keep_dir else None},
                    Confidence.CONFIRMED, Provenance.EXTRACTED, "Apktool decoded resources", rel)
        ]
        if manifest_text:
            findings.append(
                Finding(STAGE, "Apktool", "manifest", "decoded_manifest_xml",
                        {"xml": manifest_text}, Confidence.CONFIRMED, Provenance.EXTRACTED,
                        "Decoded AndroidManifest.xml from Apktool", rel)
            )
        return "ok", findings, res
