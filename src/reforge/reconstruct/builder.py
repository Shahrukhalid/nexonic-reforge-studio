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


def _clean_stale_artifacts(dist: Path, name: str) -> None:
    """Remove any stale or partial binaries for this project name from the output directory."""
    if dist.is_dir():
        for f in dist.glob(f"{name}.*"):
            try:
                f.unlink(missing_ok=True)
            except Exception:
                pass


def detect_build_configuration(project_dir: Path) -> dict[str, str]:
    """Detect language, target name, and primary entry point for a clean-room project."""
    project_dir = Path(project_dir)
    cfg: dict[str, str] = {"language": "unknown", "name": project_dir.name, "entry": ""}

    if (project_dir / "pyproject.toml").is_file() or (project_dir / "setup.py").is_file() or any(project_dir.rglob("*.py")):
        cfg["language"] = "python"
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
    elif (project_dir / "CMakeLists.txt").is_file() or (project_dir / "Makefile").is_file() or any(project_dir.rglob("*.c")) or any(project_dir.rglob("*.cpp")):
        cfg["language"] = "c"
        c_entry = list(project_dir.glob("src/main.c")) or list(project_dir.glob("*.c")) or list(project_dir.glob("*.cpp"))
        if c_entry:
            cfg["entry"] = str(c_entry[0])
    elif list(project_dir.glob("*.csproj")) or list(project_dir.glob("*.sln")) or any(project_dir.rglob("*.cs")):
        cfg["language"] = "csharp"
        cs_entry = list(project_dir.glob("Program.cs")) or list(project_dir.glob("src/Program.cs"))
        if cs_entry:
            cfg["entry"] = str(cs_entry[0])
    elif (project_dir / "pom.xml").is_file() or (project_dir / "build.gradle").is_file() or any(project_dir.rglob("*.java")):
        cfg["language"] = "java"
        java_entry = list(project_dir.glob("**/App.java")) or list(project_dir.glob("**/Main.java")) or list(project_dir.rglob("*.java"))
        if java_entry:
            cfg["entry"] = str(java_entry[0])

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
    cmd: list[str] = []

    if lang == "python":
        entry = cfg.get("entry")
        if not entry:
            _clean_stale_artifacts(dist, name)
            return BuildResult(
                success=False,
                artifacts=[],
                output_dir=dist,
                stdout="",
                stderr="No Python entry point found (e.g. main.py)",
                duration=0.0,
            )

        if target == "binary":
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
        if res.ok:
            # Copy release binary to dist
            target_bin = project_dir / "target" / "release" / (f"{name}.exe" if sys.platform == "win32" else name)
            if target_bin.is_file():
                shutil.copy2(target_bin, dist / target_bin.name)

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

    elif lang in ("c", "cpp"):
        # 1. Try CMake if CMakeLists.txt exists
        cmake = shutil.which("cmake")
        if (project_dir / "CMakeLists.txt").is_file() and cmake:
            build_dir = dist / "cmake_build"
            cmd_cfg = [cmake, "-B", str(build_dir), "-DCMAKE_BUILD_TYPE=Release"]
            res_cfg = run_tool(cmd_cfg, cwd=project_dir, timeout=timeout)
            if not res_cfg.ok:
                return BuildResult(
                    success=False,
                    artifacts=[],
                    output_dir=dist,
                    stdout=res_cfg.stdout,
                    stderr=res_cfg.stderr,
                    duration=time.time() - t0,
                    command=cmd_cfg,
                )
            cmd = [cmake, "--build", str(build_dir), "--config", "Release"]
            res = run_tool(cmd, cwd=project_dir, timeout=timeout)
            # Find and copy output executables
            for p in build_dir.rglob("*"):
                if p.is_file() and (p.suffix in (".exe", ".dll", ".so", ".dylib") or (sys.platform != "win32" and not p.suffix)):
                    if "CMakeFiles" not in str(p):
                        shutil.copy2(p, dist / p.name)
        else:
            # 2. Direct compiler fallback (gcc, clang, cl)
            cc = shutil.which("gcc") or shutil.which("clang") or shutil.which("cl")
            if not cc:
                return BuildResult(
                    success=False,
                    artifacts=[],
                    output_dir=dist,
                    stdout="",
                    stderr="No C/C++ compiler found on PATH (requires cmake, gcc, clang, or cl).",
                    duration=0.0,
                )
            sources = [str(p) for p in project_dir.rglob("*.c")] + [str(p) for p in project_dir.rglob("*.cpp")]
            sources = [s for s in sources if "test" not in s.lower() and "dist" not in s]
            if not sources:
                sources = [str(p) for p in project_dir.rglob("*.c")] or [str(p) for p in project_dir.rglob("*.cpp")]

            out_bin = dist / (f"{name}.exe" if sys.platform == "win32" else name)
            if "cl" in Path(cc).name.lower():
                cmd = [cc, "/O2", f"/Fe:{out_bin}"] + sources
            else:
                cmd = [cc, "-O2", "-o", str(out_bin)] + sources
            res = run_tool(cmd, cwd=project_dir, timeout=timeout)

    elif lang == "csharp":
        dotnet = shutil.which("dotnet")
        if not dotnet:
            return BuildResult(
                success=False,
                artifacts=[],
                output_dir=dist,
                stdout="",
                stderr=".NET SDK (dotnet) not found on PATH.",
                duration=0.0,
            )
        if target == "binary":
            cmd = [dotnet, "publish", "-c", "Release", "-o", str(dist)]
        else:
            cmd = [dotnet, "build", "-c", "Release", "-o", str(dist)]
        res = run_tool(cmd, cwd=project_dir, timeout=timeout)

    elif lang == "java":
        mvn = shutil.which("mvn") or shutil.which("mvn.cmd")
        gradle = shutil.which("gradle") or shutil.which("gradle.bat")
        javac = shutil.which("javac")

        if (project_dir / "pom.xml").is_file() and mvn:
            cmd = [mvn, "package", "-DskipTests=true"]
            res = run_tool(cmd, cwd=project_dir, timeout=timeout)
            # Copy jars from target/
            for j in (project_dir / "target").glob("*.jar"):
                shutil.copy2(j, dist / j.name)
        elif (project_dir / "build.gradle").is_file() and gradle:
            cmd = [gradle, "build", "-x", "test"]
            res = run_tool(cmd, cwd=project_dir, timeout=timeout)
            for j in project_dir.glob("build/libs/*.jar"):
                shutil.copy2(j, dist / j.name)
        elif javac:
            classes_dir = dist / "classes"
            classes_dir.mkdir(parents=True, exist_ok=True)
            sources = [str(p) for p in project_dir.rglob("*.java") if "test" not in str(p).lower()]
            if not sources:
                sources = [str(p) for p in project_dir.rglob("*.java")]
            cmd = [javac, "-d", str(classes_dir)] + sources
            res = run_tool(cmd, cwd=project_dir, timeout=timeout)
            if res.ok:
                # Package classes into JAR
                jar_bin = shutil.which("jar")
                out_jar = dist / f"{name}.jar"
                if jar_bin:
                    run_tool([jar_bin, "cf", str(out_jar), "-C", str(classes_dir), "."], cwd=project_dir)
                else:
                    import zipfile
                    with zipfile.ZipFile(out_jar, "w", compression=zipfile.ZIP_DEFLATED) as zf:
                        for cf in classes_dir.rglob("*"):
                            if cf.is_file():
                                zf.write(cf, arcname=cf.relative_to(classes_dir).as_posix())
        else:
            return BuildResult(
                success=False,
                artifacts=[],
                output_dir=dist,
                stdout="",
                stderr="Java build tools not found on PATH (requires maven, gradle, or javac).",
                duration=0.0,
            )

    else:
        _clean_stale_artifacts(dist, name)
        return BuildResult(
            success=False,
            artifacts=[],
            output_dir=dist,
            stdout="",
            stderr=f"Unsupported project stack: {lang}",
            duration=0.0,
        )

    # Collect produced artifacts only if build succeeded
    artifacts: list[Path] = []
    digests: dict[str, str] = {}
    if res.ok and dist.is_dir():
        for f in dist.rglob("*"):
            if f.is_file() and not f.name.endswith((".spec", ".sha256", ".log")):
                if "build_temp" not in str(f) and "spec" not in str(f) and "cmake_build" not in str(f):
                    artifacts.append(f)

        # Calculate digests
        for a in artifacts:
            digests[a.name] = _sha256(a)

        # Bundle standalone archive if artifacts exist
        if artifacts:
            import zipfile
            zip_path = dist / f"{name}_dist.zip"
            with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
                for a in artifacts:
                    zf.write(a, arcname=a.name)
            digests[zip_path.name] = _sha256(zip_path)
            artifacts.append(zip_path)
    elif not res.ok and dist.is_dir():
        # Remove any partial or stale binaries to prevent false positive distribution
        for f in dist.glob(f"{name}.*"):
            try:
                f.unlink(missing_ok=True)
            except Exception:
                pass

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
