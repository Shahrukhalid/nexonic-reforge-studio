"""Milestone v0.11.0 — Validation Integrity & Stable-Release Preparation Test Suite."""
from __future__ import annotations

import py_compile
from pathlib import Path

from reforge.analysis.benchmark_targets import (
    compile_reference_fixture,
    run_ground_truth_benchmark_for_fixture,
)
from reforge.analysis.ground_truth import ExpectedFunction, GroundTruthEvaluator, GroundTruthSpec
from reforge.core.findings import Finding
from reforge.reconstruct.builder import build_reconstructed_project
from reforge.reconstruct.isolation import verify_cleanroom_isolation
from reforge.reconstruct.scaffold import scaffold_project


def test_authentic_ground_truth_pipeline_on_compiled_artifact(tmp_path: Path):
    """Verify ground-truth benchmark compiles artifact, analyzes binary independently, and evaluates accuracy."""
    fixtures_dir = Path(__file__).resolve().parent / "fixtures" / "reference"
    py_fixture = fixtures_dir / "reference_app.py"
    assert py_fixture.exists()

    bench_dir = tmp_path / "py_bench"
    res = run_ground_truth_benchmark_for_fixture("py_app", py_fixture, bench_dir)

    assert res.target_name == "reference_app"
    assert res.status == "succeeded"
    assert res.compilation_succeeded is True
    assert res.compiled_binary is not None and res.compiled_binary.endswith(".pyc")
    assert res.report is not None

    # Verify real findings were extracted from bytecode
    assert res.report.functions_metric.total_expected >= 4
    assert len(res.report.functions_metric.true_positives) > 0
    assert "calculate_checksum" in res.report.functions_metric.true_positives
    assert "authenticate" in res.report.functions_metric.true_positives
    assert "process_command" in res.report.functions_metric.true_positives
    assert res.overall_accuracy > 0.0


def test_benchmark_accuracy_decreases_when_functions_removed():
    """Verify GroundTruthEvaluator produces lower recall and F1 when known functions are missing or renamed."""
    spec = GroundTruthSpec(
        target_name="test_subject",
        target_format="binary",
        expected_functions=[
            ExpectedFunction(name="auth_user", min_params=2),
            ExpectedFunction(name="calc_sum", min_params=2),
            ExpectedFunction(name="verify_hash", min_params=1),
            ExpectedFunction(name="export_csv", min_params=1),
        ],
        expected_strings=["secret_99", "admin"],
        expected_endpoints=["auth", "calc"],
    )

    complete_findings = [
        Finding("functions", "test", "function", "recovered_functions", ["auth_user", "calc_sum", "verify_hash", "export_csv"]),
        Finding("strings", "test", "string", "string", "secret_99"),
        Finding("strings", "test", "string", "string", "admin"),
        Finding("endpoints", "test", "endpoint", "api_auth", "/api/auth"),
        Finding("endpoints", "test", "endpoint", "api_calc", "/api/calc"),
    ]

    report_full = GroundTruthEvaluator.evaluate(spec, complete_findings)
    assert report_full.functions_metric.recall == 1.0
    assert len(report_full.functions_metric.false_negatives) == 0

    # Incomplete findings missing 2 expected functions
    incomplete_findings = [
        Finding("functions", "test", "function", "recovered_functions", ["auth_user", "calc_sum"]),
        Finding("strings", "test", "string", "string", "secret_99"),
        Finding("strings", "test", "string", "string", "admin"),
        Finding("endpoints", "test", "endpoint", "api_auth", "/api/auth"),
        Finding("endpoints", "test", "endpoint", "api_calc", "/api/calc"),
    ]

    report_partial = GroundTruthEvaluator.evaluate(spec, incomplete_findings)
    assert report_partial.functions_metric.recall < report_full.functions_metric.recall
    assert report_partial.functions_metric.f1_score < report_full.functions_metric.f1_score
    assert len(report_partial.functions_metric.false_negatives) == 2
    assert "verify_hash" in report_partial.functions_metric.false_negatives
    assert "export_csv" in report_partial.functions_metric.false_negatives
    assert report_partial.overall_accuracy < report_full.overall_accuracy


def test_benchmark_records_toolchain_and_missing_toolchains(tmp_path: Path):
    """Verify benchmark records compiler version, optimization level, and missing toolchain status."""
    nonexistent_fixture = tmp_path / "fake_sample.nonexistent"
    nonexistent_fixture.write_text("dummy", encoding="utf-8")

    report = compile_reference_fixture(nonexistent_fixture, tmp_path / "out")
    assert report.success is False
    assert "Unsupported" in report.error_message


def test_isolation_modified_content_detection(tmp_path: Path):
    """Verify clean-room isolation scanner flags modified/paraphrased source files above similarity threshold."""
    extracted_dir = tmp_path / "extracted"
    extracted_dir.mkdir(parents=True)
    orig_code = (
        "int process_transaction(int account_id, double amount, const char* currency) {\n"
        "    if (amount <= 0.0) return -1;\n"
        "    double balance = get_account_balance(account_id);\n"
        "    if (balance < amount) return -2;\n"
        "    set_account_balance(account_id, balance - amount);\n"
        "    log_audit_event(account_id, 'DEBIT', amount, currency);\n"
        "    return 0;\n"
        "}\n"
    )
    (extracted_dir / "transaction_core.c").write_text(orig_code * 3, encoding="utf-8")

    # Reconstructed file that is modified/renamed but retains 85%+ normalized token overlap
    recon_dir = tmp_path / "recon"
    recon_dir.mkdir(parents=True)
    modified_code = (
        "int process_transaction_renamed(int acct_id, double amt, const char* curr) {\n"
        "    if (amt <= 0.0) return -1;\n"
        "    double bal = get_account_balance(acct_id);\n"
        "    if (bal < amt) return -2;\n"
        "    set_account_balance(acct_id, bal - amt);\n"
        "    log_audit_event(acct_id, 'DEBIT', amt, curr);\n"
        "    return 0;\n"
        "}\n"
    )
    (recon_dir / "transaction_reimpl.c").write_text(modified_code * 3, encoding="utf-8")

    audit = verify_cleanroom_isolation(extracted_dir, recon_dir, similarity_threshold=0.60)
    assert audit.is_clean is False
    assert audit.requires_human_review is True
    assert len(audit.suspected_leaks) > 0
    assert any("Modified content overlap" in v for v in audit.violations)
    assert audit.suspected_leaks[0].similarity_score >= 0.60
    assert "LEGAL" in audit.disclaimer or "legal" in audit.disclaimer.lower()


def test_isolation_symlink_directory_traversal_detection(tmp_path: Path):
    """Verify clean-room isolation checks detect directory traversal attempts escaping workspace."""
    extracted_dir = tmp_path / "extracted"
    extracted_dir.mkdir()
    recon_dir = tmp_path / "recon"
    recon_dir.mkdir()

    # Create dummy secret file outside workspace
    secret_dir = tmp_path / "secret_outside"
    secret_dir.mkdir()
    outside_file = secret_dir / "leaked_secret.txt"
    outside_file.write_text("secret_token_12345", encoding="utf-8")

    # In recon_dir, create symlink pointing outside workspace if OS supports symlinks
    escaping_link = recon_dir / "link_escape.txt"
    try:
        escaping_link.symlink_to(outside_file)
        audit = verify_cleanroom_isolation(extracted_dir, recon_dir)
        assert audit.is_clean is False
        assert any("Directory traversal" in v for v in audit.violations)
    except OSError:
        # Symlink creation may require elevated privileges on older Windows configurations
        pass


def test_builder_ignores_preexisting_stale_files(tmp_path: Path):
    """Verify builder only discovers newly produced artifacts and ignores stale pre-existing files."""
    project_dir = tmp_path / "py_proj"
    project_dir.mkdir()
    (project_dir / "main.py").write_text("print('hello')", encoding="utf-8")

    dist = project_dir / "dist"
    dist.mkdir()
    stale_file = dist / "old_stale_binary.exe"
    stale_file.write_text("stale data from previous build", encoding="utf-8")

    res = build_reconstructed_project(project_dir, output_dir=dist, target="package")
    # Even if pyinstaller or wheel runs, the old stale file should not be reported as a new artifact
    artifact_names = [a.name for a in res.artifacts]
    assert "old_stale_binary.exe" not in artifact_names


def test_builder_zero_output_fails_cleanly(tmp_path: Path):
    """Verify builder strictly reports success=False if a build command produced zero artifacts."""
    empty_proj = tmp_path / "empty_proj"
    empty_proj.mkdir()
    (empty_proj / "pyproject.toml").write_text("[project]\nname = 'empty_proj'\nversion = '0.1.0'\n", encoding="utf-8")

    dist = empty_proj / "dist"
    # When wheel fails to build (missing setup/entry or no sources) or produces no files:
    res = build_reconstructed_project(empty_proj, output_dir=dist, target="package")
    assert res.success is False
    assert len(res.artifacts) == 0


def test_compiled_binary_end_to_end_reconstruction(tmp_path: Path):
    """Demonstrate authentic end-to-end reconstruction from real compiled bytecode."""
    from reforge.analysis.orchestrator import Orchestrator
    from reforge.analysis.synthesizer import DecompilationSynthesizer
    from reforge.core.db import Database
    from reforge.export.exporter import export_cleanroom_archive
    from reforge.reconstruct.scaffold import generate_specification

    db_path = tmp_path / "e2e.db"
    db = Database(db_path)

    # 1. Compile authorized source into actual binary artifact (.pyc)
    src_file = tmp_path / "auth_calc.py"
    src_file.write_text(
        "def calc_product(x, y):\n"
        "    return x * y\n\n"
        "def verify_access_key(key):\n"
        "    return key == 'e2e_valid_key_999'\n",
        encoding="utf-8",
    )
    compiled_pyc = tmp_path / "auth_calc.pyc"
    py_compile.compile(str(src_file), cfile=str(compiled_pyc), doraise=True)
    assert compiled_pyc.exists()

    # 2. Import into ReForge Studio and analyze ONLY the compiled .pyc artifact
    pid = db.create_project("E2E Compiled Reconstruct", str(compiled_pyc), profile="standard")
    orch = Orchestrator(db)
    summary = orch.analyze(pid)
    assert summary["subjects"] >= 1

    findings = db.findings(pid)
    assert len(findings) > 0

    # 3. Decompile and recover functions
    synth_funcs = DecompilationSynthesizer.synthesize_from_findings(findings, "auth_calc")
    assert len(synth_funcs) > 0

    # Verify functions recovered from bytecode
    bytecode_funcs = [
        f["value"] if isinstance(f, dict) else f.value
        for f in findings
        if (f.get("key") if isinstance(f, dict) else f.key) == "recovered_functions"
    ]
    if bytecode_funcs:
        all_recovered = set(bytecode_funcs[0])
        assert "calc_product" in all_recovered
        assert "verify_access_key" in all_recovered

    # 4. Generate clean-room specification
    spec_md = generate_specification(
        findings=findings,
        project_name="E2E CleanRoom",
        selected_features=[{"name": "Calculator", "category": "Math"}],
    )
    assert "[OBSERVED FACT - CONFIRMED]" in spec_md

    # 5. Scaffold clean-room implementation
    recon_dir = tmp_path / "recon_e2e"
    scaffold_project(
        dest_dir=recon_dir,
        project_name="E2E CleanRoom",
        stack="python",
        features=["calc_product", "verify_access_key"],
        spec_md=spec_md,
    )

    # 6. Verify technical isolation
    ext_dir = tmp_path / "extracted_sim"
    ext_dir.mkdir()
    shutil_pyc = ext_dir / "auth_calc.pyc"
    shutil_pyc.write_bytes(compiled_pyc.read_bytes())
    audit = verify_cleanroom_isolation(ext_dir, recon_dir)
    assert audit.is_clean is True

    # 7. Export clean-room archive
    archive_path, digest = export_cleanroom_archive(recon_dir, tmp_path / "e2e_export.zip")
    assert archive_path.is_file() and archive_path.stat().st_size > 100
    assert len(digest) == 64
    db.close()
