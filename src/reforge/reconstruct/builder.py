"""Native compiler and builder integration for reconstructed clean-room projects."""
from __future__ import annotations

import hashlib
import json
import shutil
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

from ..core.safety import run_tool


def _sha256(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        while chunk := f.read(1 << 20):
            h.update(chunk)
    return h.hexdigest()


@dataclass
class BuildResult:
    success: bool
    artifacts: list[Path]
    output_dir: Path
    stdout: str
    stderr: str
    duration: float
    command: list[str] = field(default_factory=list)
    digests: dict[str, str] = field(default_factory=dict)


def detect_build_configuration(project_dir: Path) -> dict[str, str]:
    """Detect language, target name, and primary entry point for a clean-room project."""
    project_dir = Path(project_dir)
    cfg: dict[str, str] = {"language": "unknown", "name": project_dir.name, "entry": ""}

    if (project_dir / "pyproject.toml").is_file():
        cfg["language"] = "python"
        # Search for entry script
        src_py = list(project_dir.glob("src/**/main.py")) or list(project_dir.glob("*.py"))
        if src_py:
            cfg["entry"] = str(src_py[0])
    elif (project_dir / "package.json").is_file():
        cfg["language"] = "typescript"
        cfg["entry"] = "index.ts" if (project_dir / "src" / "index.ts").is_file() else "index.js"
    elif (project_dir / "Cargo.toml").is_file():
        cfg["language"] = "rust"
        cfg["entry"] = "src/main.rs"
    elif (project_dir / "go.mod").is_file():
        cfg["language"] = "go"
        cfg["entry"] = "main.go"
    return cfg


def build_reconstructed_project(
    project_dir: Path,
    output_dir: Path | None = None,
    target: str = "binary",
    timeout: int = 300,
) -> BuildResult:
    """Compile and package reconstructed clean-room software into native desktop binaries or packages."""
    project_dir = Path(project_dir)
    cfg = detect_build_configuration(project_dir)
    dist = output_dir or (project_dir / "dist")
    dist.mkdir(parents=True, exist_ok=True)

    t0 = time.time()
    lang = cfg["language"]
    name = cfg["name"]

    if lang == "python":
        entry = cfg.get("entry")
        if not entry:
            return BuildResult(
                success=False,
                artifacts=[],
                output_dir=dist,
                stdout="",
                stderr="No Python entry point found (e.g. main.py)",
                duration=0.0,
            )

        if target == "binary":
            # PyInstaller desktop compilation
            cmd = [
                sys.executable,
                "-m",
                "PyInstaller",
                "--noconfirm",
                "--clean",
                "--onefile",
                "--name",
                name,
                "--distpath",
                str(dist),
                "--workpath",
                str(dist / "build_temp"),
                "--specpath",
                str(dist / "spec"),
                entry,
            ]
        else:
            # Package wheel
            cmd = [sys.executable, "-m", "pip", "wheel", "--no-deps", "-w", str(dist), "."]

        res = run_tool(cmd, cwd=project_dir, timeout=timeout)

    elif lang == "rust":
        cargo = shutil.which("cargo")
        if not cargo:
            return BuildResult(
                success=False,
                artifacts=[],
                output_dir=dist,
                stdout="",
                stderr="Rust compiler (cargo) not found on PATH.",
                duration=0.0,
            )
        cmd = [cargo, "build", "--release"]
        res = run_tool(cmd, cwd=project_dir, timeout=timeout)

    elif lang == "go":
        go_bin = shutil.which("go")
        if not go_bin:
            return BuildResult(
                success=False,
                artifacts=[],
                output_dir=dist,
                stdout="",
                stderr="Go compiler (go) not found on PATH.",
                duration=0.0,
            )
        out_bin = dist / (f"{name}.exe" if sys.platform == "win32" else name)
        cmd = [go_bin, "build", "-o", str(out_bin), "."]
        res = run_tool(cmd, cwd=project_dir, timeout=timeout)

    elif lang == "typescript":
        npm = shutil.which("npm") or shutil.which("npm.cmd")
        if not npm:
            return BuildResult(
                success=False,
                artifacts=[],
                output_dir=dist,
                stdout="",
                stderr="npm toolchain not found on PATH.",
                duration=0.0,
            )
        cmd = [npm, "run", "build"]
        res = run_tool(cmd, cwd=project_dir, timeout=timeout)

    else:
        return BuildResult(
            success=False,
            artifacts=[],
            output_dir=dist,
            stdout="",
            stderr=f"Unsupported project stack: {lang}",
            duration=0.0,
        )

    # Collect produced artifacts
    artifacts: list[Path] = []
    if dist.is_dir():
        for f in dist.rglob("*"):
            if f.is_file() and not f.name.endswith((".spec", ".sha256", ".log")):
                # Avoid temp build objects
                if "build_temp" not in str(f) and "spec" not in str(f):
                    artifacts.append(f)

    # Calculate digests
    digests: dict[str, str] = {}
    for a in artifacts:
        digests[a.name] = _sha256(a)

    # Bundle standalone archive if artifacts exist
    if res.ok and artifacts:
        import zipfile
        zip_path = dist / f"{name}_dist.zip"
        with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            for a in artifacts:
                zf.write(a, arcname=a.name)
        digests[zip_path.name] = _sha256(zip_path)
        artifacts.append(zip_path)

    manifest_file = dist / "build_manifest.json"
    manifest_data = {
        "project": name,
        "language": lang,
        "target": target,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "success": res.ok,
        "artifacts": [
            {"filename": a.name, "size": a.stat().st_size, "sha256": digests.get(a.name, "")}
            for a in artifacts
        ],
    }
    manifest_file.write_text(json.dumps(manifest_data, indent=2), encoding="utf-8")

    # Clean temporary directories if present
    shutil.rmtree(dist / "build_temp", ignore_errors=True)
    shutil.rmtree(dist / "spec", ignore_errors=True)

    return BuildResult(
        success=res.ok,
        artifacts=artifacts,
        output_dir=dist,
        stdout=res.stdout,
        stderr=res.stderr,
        duration=time.time() - t0,
        command=cmd,
        digests=digests,
    )
