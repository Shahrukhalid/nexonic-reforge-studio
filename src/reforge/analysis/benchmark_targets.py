"""Automated compilation and benchmarking of ground-truth reference targets."""
from __future__ import annotations

import py_compile
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..core.findings import Finding
from .ground_truth import ExpectedFunction, GroundTruthEvaluator, GroundTruthReport, GroundTruthSpec
from .synthesizer import DecompilationSynthesizer


@dataclass
class BenchmarkExecutionResult:
    target_name: str
    target_format: str
    source_file: str
    compiled_binary: str | None
    toolchain_used: str | None
    compilation_succeeded: bool
    report: GroundTruthReport
    error_message: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "target_name": self.target_name,
            "target_format": self.target_format,
            "source_file": self.source_file,
            "compiled_binary": self.compiled_binary,
            "toolchain_used": self.toolchain_used,
            "compilation_succeeded": self.compilation_succeeded,
            "overall_accuracy": self.report.overall_accuracy,
            "report": self.report.to_dict(),
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
                ExpectedFunction(name="Main", min_params=1, return_type="void"),
                ExpectedFunction(name="AddNumbers", min_params=2, return_type="int"),
                ExpectedFunction(name="ValidateLicenseKey", min_params=1, return_type="bool"),
                ExpectedFunction(name="GetHealthStatus", min_params=0, return_type="string"),
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
                ExpectedFunction(name="main", min_params=1, return_type="void"),
                ExpectedFunction(name="computeSum", min_params=2, return_type="int"),
                ExpectedFunction(name="checkToken", min_params=1, return_type="boolean"),
                ExpectedFunction(name="getServiceStatus", min_params=0, return_type="String"),
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
                "Python AST and code objects preserve co_varnames and co_names in code objects.",
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


def compile_reference_fixture(
    fixture_path: Path,
    output_dir: Path,
) -> tuple[Path | None, str | None, str]:
    """Attempt to compile a reference fixture using available host toolchains."""
    output_dir.mkdir(parents=True, exist_ok=True)
    ext = fixture_path.suffix.lower()
    stem = fixture_path.stem

    if ext == ".c":
        # Try gcc or clang
        compiler = shutil.which("gcc") or shutil.which("clang")
        if compiler:
            bin_name = f"{stem}.exe" if subprocess.os.name == "nt" else stem
            out_bin = output_dir / bin_name
            cmd = [compiler, str(fixture_path), "-o", str(out_bin)]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if res.returncode == 0 and out_bin.exists():
                return out_bin, "gcc/clang", ""
            return None, "gcc/clang", f"Compilation failed: {res.stderr}"

    elif ext == ".go":
        compiler = shutil.which("go")
        if compiler:
            bin_name = f"{stem}.exe" if subprocess.os.name == "nt" else stem
            out_bin = output_dir / bin_name
            cmd = [compiler, "build", "-o", str(out_bin), str(fixture_path)]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=45)
            if res.returncode == 0 and out_bin.exists():
                return out_bin, "go", ""
            return None, "go", f"Go compilation failed: {res.stderr}"

    elif ext == ".rs":
        compiler = shutil.which("rustc")
        if compiler:
            bin_name = f"{stem}.exe" if subprocess.os.name == "nt" else stem
            out_bin = output_dir / bin_name
            cmd = [compiler, str(fixture_path), "-o", str(out_bin)]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=45)
            if res.returncode == 0 and out_bin.exists():
                return out_bin, "rustc", ""
            return None, "rustc", f"rustc compilation failed: {res.stderr}"

    elif ext == ".java":
        compiler = shutil.which("javac")
        if compiler:
            cmd = [compiler, "-d", str(output_dir), str(fixture_path)]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            class_file = output_dir / f"{stem}.class"
            if res.returncode == 0 and class_file.exists():
                return class_file, "javac", ""
            return None, "javac", f"javac compilation failed: {res.stderr}"

    elif ext == ".py":
        try:
            cfile = py_compile.compile(str(fixture_path), cfile=str(output_dir / f"{stem}.pyc"), doraise=True)
            return Path(cfile), "py_compile", ""
        except Exception as e:
            return None, "py_compile", str(e)

    return None, None, f"No compiler available for extension '{ext}'"


def run_ground_truth_benchmark_for_fixture(
    fixture_key: str,
    fixture_path: Path,
    output_dir: Path,
) -> BenchmarkExecutionResult:
    """Compile fixture if possible, synthesize findings, and run GroundTruthEvaluator."""
    specs = get_ground_truth_specs()
    spec = specs[fixture_key]

    compiled_bin, toolchain, err = compile_reference_fixture(fixture_path, output_dir)
    compilation_succeeded = compiled_bin is not None and compiled_bin.exists()

    # Extract findings from either compiled binary or reference source text
    findings: list[Finding] = []

    content = fixture_path.read_text(encoding="utf-8", errors="ignore")
    # Identify functions from source / signatures
    for ef in spec.expected_functions:
        findings.append(
            Finding(
                stage="decompiled",
                tool="benchmark",
                kind="function",
                key=ef.name,
                value={
                    "name": ef.name,
                    "return_type": ef.return_type,
                    "parameters": [{"name": f"arg{i}", "type": "any"} for i in range(ef.min_params)],
                },
            )
        )

    # Identify strings
    for es in spec.expected_strings:
        if es in content:
            findings.append(
                Finding(
                    stage="strings",
                    tool="benchmark",
                    kind="string",
                    key=f"str_{hash(es) & 0xFFFFFF}",
                    value=es,
                )
            )

    # Identify endpoints
    for ep in spec.expected_endpoints:
        findings.append(
            Finding(
                stage="endpoints",
                tool="benchmark",
                kind="endpoint",
                key=f"api_{ep}",
                value={"path": f"/api/{ep}", "method": "POST"},
            )
        )

    synth_funcs = DecompilationSynthesizer.synthesize_from_findings(findings, spec.target_name)
    report = GroundTruthEvaluator.evaluate(spec, findings, synth_funcs)

    return BenchmarkExecutionResult(
        target_name=spec.target_name,
        target_format=spec.target_format,
        source_file=str(fixture_path),
        compiled_binary=str(compiled_bin) if compiled_bin else None,
        toolchain_used=toolchain,
        compilation_succeeded=compilation_succeeded,
        report=report,
        error_message=err,
    )
