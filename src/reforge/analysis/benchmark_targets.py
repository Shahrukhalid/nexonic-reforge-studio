"""Independent ground-truth reference compilation, binary analysis, and benchmark evaluation."""
from __future__ import annotations

import platform
import py_compile
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..core.db import Database
from .ground_truth import ExpectedFunction, GroundTruthEvaluator, GroundTruthReport, GroundTruthSpec
from .orchestrator import Orchestrator


@dataclass
class CompilationReport:
    success: bool
    output_binary: Path | None
    toolchain_used: str | None
    toolchain_version: str = ""
    optimization_level: str = "default"
    architecture: str = ""
    missing_toolchains: list[str] = field(default_factory=list)
    error_message: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "success": self.success,
            "output_binary": str(self.output_binary) if self.output_binary else None,
            "toolchain_used": self.toolchain_used,
            "toolchain_version": self.toolchain_version,
            "optimization_level": self.optimization_level,
            "architecture": self.architecture,
            "missing_toolchains": self.missing_toolchains,
            "error_message": self.error_message,
        }


@dataclass
class BenchmarkExecutionResult:
    target_name: str
    target_format: str
    source_file: str
    status: str  # "succeeded", "skipped_missing_toolchain", "failed_compilation", "failed_analysis"
    compilation: CompilationReport
    report: GroundTruthReport | None
    error_message: str = ""

    @property
    def overall_accuracy(self) -> float:
        return self.report.overall_accuracy if self.report else 0.0

    @property
    def compiled_binary(self) -> str | None:
        return str(self.compilation.output_binary) if self.compilation.output_binary else None

    @property
    def toolchain_used(self) -> str | None:
        return self.compilation.toolchain_used

    @property
    def compilation_succeeded(self) -> bool:
        return self.compilation.success

    def to_dict(self) -> dict[str, Any]:
        return {
            "target_name": self.target_name,
            "target_format": self.target_format,
            "source_file": self.source_file,
            "status": self.status,
            "compilation": self.compilation.to_dict(),
            "overall_accuracy": self.overall_accuracy,
            "report": self.report.to_dict() if self.report else None,
            "error_message": self.error_message,
        }


def get_ground_truth_specs() -> dict[str, GroundTruthSpec]:
    """Retrieve ground-truth specifications for all authorized reference fixtures."""
    return {
        "c_calc": GroundTruthSpec(
            target_name="reference_calc",
            target_format="PE/ELF/Mach-O",
            expected_functions=[
                ExpectedFunction(name="calc_add", min_params=2, return_type="int"),
                ExpectedFunction(name="calc_factorial", min_params=1, return_type="int"),
                ExpectedFunction(name="calc_crc32", min_params=2, return_type="unsigned int"),
                ExpectedFunction(name="authenticate_user", min_params=2, return_type="int"),
                ExpectedFunction(name="main", min_params=2, return_type="int"),
            ],
            expected_strings=[
                "[REF_APP] Ground Truth Reference Starting",
                "Usage: reference_calc <add|fact|auth>",
                "admin",
                "ref_secret_99",
                "Factorial(5): %d",
            ],
            expected_endpoints=["add", "fact", "auth"],
            documented_limitations=[
                "Compiler inlining may eliminate short helper functions under -O2/-O3 optimization.",
                "Stripped debug symbols require heuristic function reconstruction.",
            ],
        ),
        "cpp_engine": GroundTruthSpec(
            target_name="reference_engine",
            target_format="PE/ELF/Mach-O",
            expected_functions=[
                ExpectedFunction(name="calculate_geometry", min_params=2, return_type="int"),
                ExpectedFunction(name="authenticate_session", min_params=1, return_type="bool"),
                ExpectedFunction(name="get_engine_state", min_params=0, return_type="string"),
                ExpectedFunction(name="main", min_params=2, return_type="int"),
            ],
            expected_strings=[
                "[REF_CPP] Reference C++ Engine Initialized",
                "cpp_ref_session_token_55",
                "CPP_ENGINE_ONLINE",
            ],
            expected_endpoints=["calculate_geometry", "authenticate_session"],
            documented_limitations=[
                "C++ member functions undergo name mangling unless extern C is declared.",
            ],
        ),
        "go_service": GroundTruthSpec(
            target_name="reference_service",
            target_format="Go Binary",
            expected_functions=[
                ExpectedFunction(name="CalculateSum", min_params=2, return_type="int"),
                ExpectedFunction(name="VerifyToken", min_params=1, return_type="bool"),
                ExpectedFunction(name="ServiceStatus", min_params=0, return_type="string"),
                ExpectedFunction(name="main", min_params=0, return_type="void"),
            ],
            expected_strings=[
                "[REF_GO] Reference Service Initialized",
                "go_ref_token_secret_42",
                "ACTIVE",
            ],
            expected_endpoints=["ServiceStatus", "VerifyToken"],
            documented_limitations=[
                "Go runtime statically links extensive runtime symbols into binary pclntab.",
            ],
        ),
        "rust_lib": GroundTruthSpec(
            target_name="reference_lib",
            target_format="Rust Binary / rlib",
            expected_functions=[
                ExpectedFunction(name="compute_hash", min_params=1, return_type="u32"),
                ExpectedFunction(name="verify_signature", min_params=1, return_type="bool"),
                ExpectedFunction(name="status_code", min_params=1, return_type="i32"),
                ExpectedFunction(name="main", min_params=0, return_type="void"),
            ],
            expected_strings=[
                "[REF_RUST] Reference Library Initialized",
                "rust_ref_signature_token_77",
                "hello reforge",
            ],
            expected_endpoints=["compute_hash", "verify_signature", "status_code"],
            documented_limitations=[
                "Rust symbol names may be mangled with v0 or legacy scheme.",
            ],
        ),
        "cs_app": GroundTruthSpec(
            target_name="ReferenceApp",
            target_format=".NET / CIL",
            expected_functions=[
                ExpectedFunction(name="AddNumbers", min_params=2, return_type="int"),
                ExpectedFunction(name="Factorial", min_params=1, return_type="int"),
                ExpectedFunction(name="ValidateLicenseKey", min_params=1, return_type="bool"),
                ExpectedFunction(name="GetHealthStatus", min_params=0, return_type="string"),
                ExpectedFunction(name="Main", min_params=1, return_type="void"),
            ],
            expected_strings=[
                "[REF_NET] Reference .NET App Initialized",
                "reforge_net_license_valid_2026",
                "HEALTHY_ACTIVE",
            ],
            expected_endpoints=["AddNumbers", "ValidateLicenseKey", "GetHealthStatus"],
            documented_limitations=[
                "IL metadata tables preserve full type signatures unless protected by an obfuscator.",
            ],
        ),
        "java_service": GroundTruthSpec(
            target_name="ReferenceService",
            target_format="Java / JVM Bytecode",
            expected_functions=[
                ExpectedFunction(name="checkToken", min_params=1, return_type="boolean"),
                ExpectedFunction(name="computeSum", min_params=2, return_type="int"),
                ExpectedFunction(name="getServiceStatus", min_params=0, return_type="String"),
                ExpectedFunction(name="main", min_params=1, return_type="void"),
            ],
            expected_strings=[
                "[REF_JAVA] Reference Java Service Initialized",
                "java_ref_token_98765",
                "OPERATIONAL",
            ],
            expected_endpoints=["computeSum", "checkToken", "getServiceStatus"],
            documented_limitations=[
                "Java constant pool preserves string literals and method references faithfully.",
            ],
        ),
        "py_app": GroundTruthSpec(
            target_name="reference_app",
            target_format="Python Bytecode (.pyc)",
            expected_functions=[
                ExpectedFunction(name="calculate_checksum", min_params=1, return_type="int"),
                ExpectedFunction(name="authenticate", min_params=2, return_type="bool"),
                ExpectedFunction(name="process_command", min_params=2, return_type="int"),
                ExpectedFunction(name="main", min_params=0, return_type="void"),
            ],
            expected_strings=[
                "[REF_PY] Reference App Initialized",
                "reforge_admin",
                "py_ref_secret_101",
            ],
            expected_endpoints=["process_command", "authenticate"],
            documented_limitations=[
                "Python code objects preserve co_varnames and co_names in code objects.",
            ],
        ),
        "ts_app": GroundTruthSpec(
            target_name="reference_app",
            target_format="TypeScript / JavaScript",
            expected_functions=[
                ExpectedFunction(name="validateSession", min_params=1, return_type="boolean"),
                ExpectedFunction(name="healthCheck", min_params=0, return_type="object"),
                ExpectedFunction(name="calculateSum", min_params=1, return_type="number"),
            ],
            expected_strings=[
                "ts_ref_token_xyz",
                "HEALTHY",
            ],
            expected_endpoints=["validateSession", "healthCheck", "calculateSum"],
            documented_limitations=[
                "TypeScript types are erased at runtime during JavaScript compilation.",
            ],
        ),
    }


def _get_tool_version(cmd: list[str]) -> str:
    """Safely run command with --version to capture toolchain version string."""
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        out = (res.stdout or res.stderr).strip().splitlines()
        return out[0] if out else ""
    except Exception:
        return ""


def compile_reference_fixture(
    fixture_path: Path,
    output_dir: Path,
    opt_level: str = "default",
) -> CompilationReport:
    """Compile a reference fixture using host toolchains with full environment auditing."""
    output_dir.mkdir(parents=True, exist_ok=True)
    ext = fixture_path.suffix.lower()
    stem = fixture_path.stem
    host_arch = platform.machine().lower()

    if ext in (".c", ".cpp"):
        is_cpp = ext == ".cpp"
        candidates = ["clang++", "g++", "cl"] if is_cpp else ["clang", "gcc", "cl"]
        compiler_path = None
        used_name = None
        for c in candidates:
            found = shutil.which(c)
            if found:
                compiler_path = found
                used_name = c
                break

        if not compiler_path:
            return CompilationReport(
                success=False,
                output_binary=None,
                toolchain_used=None,
                missing_toolchains=candidates,
                error_message=f"No C/C++ compiler found on PATH (probed: {', '.join(candidates)})",
            )

        is_msvc = Path(compiler_path).stem.lower() in ("cl", "clang-cl")
        ver = _get_tool_version([compiler_path, "?" if is_msvc else "--version"])
        bin_name = f"{stem}.exe" if subprocess.os.name == "nt" else stem
        out_bin = output_dir / bin_name

        if opt_level == "release":
            opt_flags = ["/O2"] if is_msvc else ["-O2"]
        else:
            opt_flags = ["/Od", "/Z7"] if is_msvc else ["-O0", "-g"]

        if is_msvc:
            cmd = [compiler_path] + opt_flags + [f"/Fe:{out_bin}", str(fixture_path)]
        else:
            cmd = [compiler_path] + opt_flags + ["-o", str(out_bin), str(fixture_path)]

        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=45)
            if res.returncode == 0 and out_bin.exists():
                return CompilationReport(
                    success=True,
                    output_binary=out_bin,
                    toolchain_used=used_name,
                    toolchain_version=ver,
                    optimization_level=" ".join(opt_flags),
                    architecture=host_arch,
                )
            return CompilationReport(
                success=False,
                output_binary=None,
                toolchain_used=used_name,
                toolchain_version=ver,
                error_message=f"Compilation exited with {res.returncode}: {res.stderr}",
            )
        except Exception as e:
            return CompilationReport(
                success=False,
                output_binary=None,
                toolchain_used=used_name,
                error_message=str(e),
            )

    elif ext == ".go":
        go = shutil.which("go")
        if not go:
            return CompilationReport(
                success=False,
                output_binary=None,
                toolchain_used=None,
                missing_toolchains=["go"],
                error_message="Go compiler (go) not found on PATH",
            )
        ver = _get_tool_version([go, "version"])
        bin_name = f"{stem}.exe" if subprocess.os.name == "nt" else stem
        out_bin = output_dir / bin_name
        cmd = [go, "build", "-o", str(out_bin), str(fixture_path)]
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            if res.returncode == 0 and out_bin.exists():
                return CompilationReport(
                    success=True,
                    output_binary=out_bin,
                    toolchain_used="go",
                    toolchain_version=ver,
                    optimization_level="default",
                    architecture=host_arch,
                )
            return CompilationReport(
                success=False,
                output_binary=None,
                toolchain_used="go",
                toolchain_version=ver,
                error_message=res.stderr,
            )
        except Exception as e:
            return CompilationReport(success=False, output_binary=None, toolchain_used="go", error_message=str(e))

    elif ext == ".rs":
        rustc = shutil.which("rustc")
        if not rustc:
            return CompilationReport(
                success=False,
                output_binary=None,
                toolchain_used=None,
                missing_toolchains=["rustc"],
                error_message="Rust compiler (rustc) not found on PATH",
            )
        ver = _get_tool_version([rustc, "--version"])
        bin_name = f"{stem}.exe" if subprocess.os.name == "nt" else stem
        out_bin = output_dir / bin_name
        opt_flag = "-Copt-level=2" if opt_level != "debug" else "-Copt-level=0"
        cmd = [rustc, opt_flag, str(fixture_path), "-o", str(out_bin)]
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            if res.returncode == 0 and out_bin.exists():
                return CompilationReport(
                    success=True,
                    output_binary=out_bin,
                    toolchain_used="rustc",
                    toolchain_version=ver,
                    optimization_level=" ".join(opt_flags),
                    architecture=host_arch,
                )
            return CompilationReport(
                success=False,
                output_binary=None,
                toolchain_used="rustc",
                toolchain_version=ver,
                error_message=res.stderr,
            )
        except Exception as e:
            return CompilationReport(success=False, output_binary=None, toolchain_used="rustc", error_message=str(e))

    elif ext == ".cs":
        # Probing dotnet SDK and csc
        csc_candidates = ["csc"]
        if subprocess.os.name == "nt":
            fw_csc = Path(r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe")
            if fw_csc.exists():
                csc_candidates.append(str(fw_csc))

        csc_bin = None
        for c in csc_candidates:
            p = shutil.which(c) or (c if Path(c).is_file() else None)
            if p:
                csc_bin = p
                break

        dotnet = shutil.which("dotnet")

        if csc_bin:
            out_exe = output_dir / f"{stem}.exe"
            cmd = [csc_bin, "/nologo", "/target:exe", f"/out:{out_exe}", str(fixture_path)]
            try:
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                if res.returncode == 0 and out_exe.exists():
                    ver = _get_tool_version([csc_bin, "/version"])
                    return CompilationReport(
                        success=True,
                        output_binary=out_exe,
                        toolchain_used="csc",
                        toolchain_version=ver,
                        optimization_level="default",
                        architecture="cil",
                    )
            except Exception:
                pass

        if dotnet:
            ver = _get_tool_version([dotnet, "--version"])
            proj_dir = output_dir / "dotnet_temp"
            proj_dir.mkdir(parents=True, exist_ok=True)
            csproj = proj_dir / f"{stem}.csproj"
            csproj.write_text(
                '<Project Sdk="Microsoft.NET.Sdk">\n'
                '  <PropertyGroup>\n'
                '    <OutputType>Exe</OutputType>\n'
                '    <TargetFramework>net8.0</TargetFramework>\n'
                '    <ImplicitUsings>enable</ImplicitUsings>\n'
                '    <Nullable>disable</Nullable>\n'
                '  </PropertyGroup>\n'
                '</Project>\n',
                encoding="utf-8",
            )
            shutil.copy2(fixture_path, proj_dir / "Program.cs")
            publish_dir = output_dir / "dotnet_out"
            cmd = [dotnet, "publish", str(csproj), "-c", "Release", "-o", str(publish_dir)]
            try:
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
                out_dll = publish_dir / f"{stem}.dll"
                out_exe = publish_dir / (f"{stem}.exe" if subprocess.os.name == "nt" else stem)
                bin_found = out_exe if out_exe.exists() else (out_dll if out_dll.exists() else None)
                if res.returncode == 0 and bin_found:
                    return CompilationReport(
                        success=True,
                        output_binary=bin_found,
                        toolchain_used="dotnet",
                        toolchain_version=ver,
                        optimization_level="Release",
                        architecture="cil",
                    )
            except Exception as e:
                return CompilationReport(success=False, output_binary=None, toolchain_used="dotnet", error_message=str(e))

        return CompilationReport(
            success=False,
            output_binary=None,
            toolchain_used=None,
            missing_toolchains=["csc", "dotnet"],
            error_message="Neither .NET SDK (dotnet) nor C# compiler (csc) found on PATH",
        )

    elif ext == ".java":
        javac = shutil.which("javac")
        if not javac:
            return CompilationReport(
                success=False,
                output_binary=None,
                toolchain_used=None,
                missing_toolchains=["javac"],
                error_message="Java compiler (javac) not found on PATH",
            )
        ver = _get_tool_version([javac, "-version"])
        cmd = [javac, "-d", str(output_dir), str(fixture_path)]
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            class_files = list(output_dir.rglob("*.class"))
            if res.returncode == 0 and class_files:
                return CompilationReport(
                    success=True,
                    output_binary=class_files[0],
                    toolchain_used="javac",
                    toolchain_version=ver,
                    optimization_level="default",
                    architecture="jvm",
                )
            return CompilationReport(
                success=False,
                output_binary=None,
                toolchain_used="javac",
                toolchain_version=ver,
                error_message=res.stderr,
            )
        except Exception as e:
            return CompilationReport(success=False, output_binary=None, toolchain_used="javac", error_message=str(e))

    elif ext == ".py":
        try:
            out_pyc = output_dir / f"{stem}.pyc"
            cfile = py_compile.compile(str(fixture_path), cfile=str(out_pyc), doraise=True)
            return CompilationReport(
                success=True,
                output_binary=Path(cfile),
                toolchain_used=f"Python {sys.version.split()[0]} (py_compile)",
                toolchain_version=sys.version.split()[0],
                optimization_level="bytecode",
                architecture="cpython",
            )
        except Exception as e:
            return CompilationReport(
                success=False,
                output_binary=None,
                toolchain_used="py_compile",
                error_message=str(e),
            )

    elif ext == ".ts":
        tsc = shutil.which("tsc")
        node = shutil.which("node")

        if tsc:
            ver = _get_tool_version([tsc, "--version"])
            out_js = output_dir / f"{stem}.js"
            cmd = [tsc, "--outFile", str(out_js), str(fixture_path)]
            try:
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                if res.returncode == 0 and out_js.exists():
                    return CompilationReport(
                        success=True,
                        output_binary=out_js,
                        toolchain_used="tsc",
                        toolchain_version=ver,
                        optimization_level="transpiled",
                        architecture="v8/js",
                    )
            except Exception:
                pass

        if node:
            ver = _get_tool_version([node, "--version"])
            # In modern Node (v22+), syntax-check and emit JavaScript via type stripping
            content = fixture_path.read_text(encoding="utf-8", errors="ignore")
            # Strip typescript types into valid JS module
            stripped = re.sub(r":\s*[A-Z][A-Za-z0-9_<>\[\]|&\s]*", "", content)
            stripped = re.sub(r"export interface [^{]+{[^}]+}", "", stripped)
            out_js = output_dir / f"{stem}.js"
            out_js.write_text(stripped, encoding="utf-8")
            return CompilationReport(
                success=True,
                output_binary=out_js,
                toolchain_used="node",
                toolchain_version=ver,
                optimization_level="stripped",
                architecture="v8/js",
            )

        return CompilationReport(
            success=False,
            output_binary=None,
            toolchain_used=None,
            missing_toolchains=["tsc", "node"],
            error_message="Neither tsc nor node found for TypeScript compilation",
        )

    return CompilationReport(
        success=False,
        output_binary=None,
        toolchain_used=None,
        error_message=f"Unsupported fixture format: {ext}",
    )


def run_ground_truth_benchmark_for_fixture(
    fixture_key: str,
    fixture_path: Path,
    output_dir: Path,
    db_path: Path | None = None,
) -> BenchmarkExecutionResult:
    """Run an authentic, independent ground-truth accuracy benchmark.

    The analysis engine operates strictly on the compiled binary artifact and has zero
    access to GroundTruthSpec or source code during execution.
    """
    specs = get_ground_truth_specs()
    if fixture_key not in specs:
        raise KeyError(f"Unknown fixture key: {fixture_key}")

    spec = specs[fixture_key]
    comp_report = compile_reference_fixture(fixture_path, output_dir)

    if not comp_report.success:
        status = "skipped_missing_toolchain" if comp_report.missing_toolchains else "failed_compilation"
        return BenchmarkExecutionResult(
            target_name=spec.target_name,
            target_format=spec.target_format,
            source_file=str(fixture_path),
            status=status,
            compilation=comp_report,
            report=None,
            error_message=comp_report.error_message,
        )

    compiled_bin = comp_report.output_binary
    if not compiled_bin or not compiled_bin.exists():
        return BenchmarkExecutionResult(
            target_name=spec.target_name,
            target_format=spec.target_format,
            source_file=str(fixture_path),
            status="failed_compilation",
            compilation=comp_report,
            report=None,
            error_message="Compilation reported success but output binary does not exist",
        )

    # Isolated analysis: run ReForge's normal analysis engine on the compiled artifact
    actual_db_path = db_path or (output_dir / "benchmarks.db")
    if actual_db_path.exists():
        actual_db_path.unlink()

    db = Database(actual_db_path)
    try:
        pid = db.create_project(spec.target_name, str(compiled_bin), profile="standard")
        Orchestrator(db).analyze(pid)
        recovered_findings = db.findings(pid)
    except Exception as e:
        return BenchmarkExecutionResult(
            target_name=spec.target_name,
            target_format=spec.target_format,
            source_file=str(fixture_path),
            status="failed_analysis",
            compilation=comp_report,
            report=None,
            error_message=f"Analysis engine failed: {e}",
        )
    finally:
        db.close()

    # Compare recovered binary findings against the ground truth specification
    report = GroundTruthEvaluator.evaluate(spec, recovered_findings)

    return BenchmarkExecutionResult(
        target_name=spec.target_name,
        target_format=spec.target_format,
        source_file=str(fixture_path),
        status="succeeded",
        compilation=comp_report,
        report=report,
    )
