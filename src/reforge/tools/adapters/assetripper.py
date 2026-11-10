"""AssetRipper adapter: extracts and inspects Unity game packages and assets."""
from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

from ...core.findings import Confidence, Finding, Provenance
from ...core.safety import ToolResult, run_tool

STAGE = "tools"
MAX_ASSETS = 500


def run_assetripper(exe: str, target: Path, rel: str, timeout: int, keep_dir: Path | None = None) -> tuple[str, list[Finding], ToolResult | None]:
    with tempfile.TemporaryDirectory(prefix="reforge-assetripper-") as tmp:
        out = Path(tmp) / "ripped"
        out.mkdir(parents=True, exist_ok=True)
        res = run_tool([exe, str(target), "-o", str(out), "-q"], timeout=timeout)
        extracted_files = [p.relative_to(out).as_posix() for p in out.rglob("*") if p.is_file()]

        if not extracted_files and not res.ok:
            return "error", [
                Finding(STAGE, "AssetRipper", "tool_error", "assetripper_failed",
                        {"rc": res.returncode, "error": (res.stderr or res.stdout)[-2000:]},
                        Confidence.CONFIRMED, subject=rel)
            ], res

        if keep_dir is not None and extracted_files:
            shutil.rmtree(keep_dir, ignore_errors=True)
            shutil.copytree(out, keep_dir)

        findings = [
            Finding(STAGE, "AssetRipper", "unity_assets", "extracted_assets",
                    {"count": len(extracted_files), "sample": sorted(extracted_files)[:MAX_ASSETS],
                     "saved_to": str(keep_dir) if keep_dir else None},
                    Confidence.CONFIRMED, Provenance.EXTRACTED, "AssetRipper Unity assets", rel)
        ]
        return "ok", findings, res
