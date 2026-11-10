"""Export utilities for clean-room code, analysis reports, and SBOM manifests."""
from __future__ import annotations

import hashlib
import json
import tarfile
import time
import zipfile
from pathlib import Path
from typing import Any

from ..analysis import report


def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        while chunk := f.read(1 << 20):
            h.update(chunk)
    return h.hexdigest()


def export_cleanroom_archive(reconstructed_dir: Path, output_archive: Path) -> tuple[Path, str]:
    """Package reconstructed clean-room project into a ZIP or tar.gz archive with SHA-256."""
    output_archive = Path(output_archive)
    output_archive.parent.mkdir(parents=True, exist_ok=True)

    if output_archive.name.endswith(".tar.gz") or output_archive.name.endswith(".tgz"):
        with tarfile.open(output_archive, "w:gz") as tar:
            for p in reconstructed_dir.rglob("*"):
                if p.is_file():
                    tar.add(p, arcname=p.relative_to(reconstructed_dir).as_posix())
    else:
        with zipfile.ZipFile(output_archive, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            for p in reconstructed_dir.rglob("*"):
                if p.is_file():
                    zf.write(p, arcname=p.relative_to(reconstructed_dir).as_posix())

    digest = sha256_file(output_archive)
    manifest_path = output_archive.with_suffix(output_archive.suffix + ".sha256")
    manifest_path.write_text(f"{digest}  {output_archive.name}\n", encoding="utf-8")
    return output_archive, digest


def export_sbom(db: Any, pid: int, output_path: Path) -> Path:
    """Generate a Software Bill of Materials (SBOM) in JSON format from analysis findings."""
    p = db.project(pid)
    rows = db.findings(pid)

    components = []
    # Dynamic libraries
    for r in rows:
        if r["key"] == "libraries" and isinstance(r["value"], list):
            for lib in r["value"]:
                components.append({
                    "type": "library",
                    "name": lib,
                    "scope": "runtime",
                    "evidence": "parsed_structure",
                })
        elif r["key"] == "package_json" and isinstance(r["value"], dict):
            for pkg, ver in r["value"].get("dependencies", {}).items():
                components.append({
                    "type": "npm_package",
                    "name": pkg,
                    "version": str(ver),
                    "scope": "runtime",
                })
        elif r["key"] == "dotnet_metadata" and isinstance(r["value"], dict):
            for ref in r["value"].get("assembly_refs", []):
                components.append({
                    "type": "dotnet_assembly",
                    "name": ref.get("name", ""),
                    "version": ref.get("version", ""),
                    "scope": "runtime",
                })

    sbom = {
        "bomFormat": "CycloneDX-Compatible",
        "specVersion": "1.5",
        "metadata": {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "component": {
                "name": p.get("name") if p else f"project_{pid}",
                "version": "1.0.0",
                "hashes": [{"alg": "SHA-256", "content": p.get("sha256") if p else ""}],
            },
            "tools": [{"vendor": "Nexonic Technologies", "name": "Nexonic ReForge Studio"}],
        },
        "components": components,
    }

    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(sbom, indent=2), encoding="utf-8")
    return output_path


def export_report_bundle(db: Any, pid: int, output_dir: Path) -> dict[str, Path]:
    """Export both Markdown and JSON analysis reports into output directory."""
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    md_path = output_dir / f"reforge_analysis_p{pid:05d}.md"
    json_path = output_dir / f"reforge_analysis_p{pid:05d}.json"
    sbom_path = output_dir / f"reforge_sbom_p{pid:05d}.json"

    report.export(db, pid, md_path)
    report.export(db, pid, json_path)
    export_sbom(db, pid, sbom_path)

    return {"markdown": md_path, "json": json_path, "sbom": sbom_path}
