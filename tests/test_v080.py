"""Milestone v0.8.0 tests: Ground truth benchmarking, genuine decompiler integration,
source-to-assembly mapping, implementation task planning, realistic behavioral tests,
and normalized structural binary diffing.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from reforge.analysis.diffing import BinaryDiffEngine
from reforge.analysis.ground_truth import (
    ExpectedFunction,
    GroundTruthEvaluator,
    GroundTruthSpec,
)
from reforge.analysis.synthesizer import (
    DecompilationSynthesizer,
    DecompiledFunction,
)
from reforge.core.findings import Finding
from reforge.reconstruct.tasks import TaskPlanner
from reforge.reconstruct.tests_gen import generate_evidence_tests, validate_generated_tests
from reforge.ui.main_window import MainWindow


def test_ground_truth_spec_and_evaluation():
    spec = GroundTruthSpec(
        target_name="reference_calc",
        target_format="PE",
        expected_functions=[
            ExpectedFunction(name="calc_add", min_params=2, return_type="int"),
            ExpectedFunction(name="calc_factorial", min_params=1, return_type="int"),
            ExpectedFunction(name="calc_crc32", min_params=2, return_type="unsigned int"),
            ExpectedFunction(name="authenticate_user", min_params=2, return_type="int"),
            ExpectedFunction(name="secret_inlined_function", min_params=0, return_type="void"),
        ],
        expected_strings=["[REF_APP] Ground Truth Reference Starting", "Usage: reference_calc"],
        expected_endpoints=["https://ref.internal/v1/auth"],
        documented_limitations=["Static analysis cannot recover stripped inlined functions without symbols."],
    )

    findings = [
        Finding("synthesizer", "reforge", "decompiled_synthesized", "calc_add", {"name": "calc_add", "address": "0x401000"}),
        Finding("synthesizer", "reforge", "decompiled_synthesized", "calc_factorial", {"name": "calc_factorial", "address": "0x401050"}),
        Finding("synthesizer", "reforge", "decompiled_synthesized", "calc_crc32", {"name": "calc_crc32", "address": "0x4010b0"}),
        Finding("synthesizer", "reforge", "decompiled_synthesized", "authenticate_user", {"name": "authenticate_user", "address": "0x401150"}),
        Finding("disasm", "capstone", "disassembly", "export:compiler_glue_helper", {"lines": ["push rbp", "ret"]}),
        Finding("strings", "floss", "string", "str_0", "[REF_APP] Ground Truth Reference Starting"),
        Finding("network", "floss", "network", "url_0", ["https://ref.internal/v1/auth"]),
    ]

    report = GroundTruthEvaluator.evaluate(spec, findings)

    # 4 of 5 functions found, 1 false negative (secret_inlined_function), 1 false positive (compiler_glue_helper)
    assert report.functions_metric.total_expected == 5
    assert "calc_add" in report.functions_metric.true_positives
    assert "secret_inlined_function" in report.functions_metric.false_negatives
    assert "compiler_glue_helper" in report.functions_metric.false_positives
    assert report.functions_metric.precision > 0.70
    assert report.functions_metric.recall == 0.80

    # Strings evaluation
    assert "[REF_APP] Ground Truth Reference Starting" in report.strings_metric.true_positives
    assert "Usage: reference_calc" in report.strings_metric.false_negatives

    # Endpoints evaluation
    assert "https://ref.internal/v1/auth" in report.endpoints_metric.true_positives

    # Markdown report generation
    md = GroundTruthEvaluator.generate_markdown_report(report)
    assert "# Nexonic ReForge Studio — Ground Truth Evaluation Report" in md
    assert "Quantitative Accuracy Breakdown" in md
    assert "Discrepancies & Limitations" in md
    assert "secret_inlined_function" in md


def test_decompilation_synthesizer_genuine_vs_heuristic_and_complexity():
    # 1. Genuine decompiler finding (e.g. from Ghidra)
    ghidra_findings = [
        Finding(
            stage="decompiler",
            tool="ghidra",
            kind="decompiled",
            key="calc_crc32",
            value={
                "tool": "ghidra",
                "code": "unsigned int calc_crc32(byte *data, int len) {\n    return 0xEDB88320;\n}",
            },
        ),
        Finding(
            stage="analysis",
            tool="ghidra",
            kind="functions",
            key="functions",
            value={"items": [{"name": "calc_crc32", "entry": "0x004010b0", "size": 64}]},
        ),
    ]

    funcs = DecompilationSynthesizer.synthesize_from_findings(ghidra_findings)
    assert len(funcs) == 1
    fn = funcs[0]
    assert fn.is_verified_decompiler is True
    assert fn.confidence_score == 1.0
    assert "[GENUINE DECOMPILER OUTPUT — EXTRACTED FROM ENGINE]" in fn.pseudocode
    assert "Engine:      Ghidra" in fn.pseudocode

    # 2. Heuristic synthesis from disassembly with CFG and Cyclomatic Complexity
    asm_lines = [
        "0x00401000  55                   push rbp",
        "0x00401001  48 89 e5             mov rbp, rsp",
        "0x00401004  85 ff                test edi, edi",
        "0x00401006  7e 0f                jle 0x00401017",
        "0x00401008  b8 01 00 00 00       mov eax, 1",
        "0x0040100d  e8 20 01 00 00       call 0x00401130",
        "0x00401012  eb 05                jmp 0x00401019",
        "0x00401017  31 c0                xor eax, eax",
        "0x00401019  5d                   pop rbp",
        "0x0040101a  c3                   ret",
    ]

    disasm_findings = [
        Finding(
            stage="disasm",
            tool="capstone",
            kind="disassembly",
            key="export:calc_branch",
            value={"arch": "x86-64", "address": "0x00401000", "lines": asm_lines},
        )
    ]

    funcs2 = DecompilationSynthesizer.synthesize_from_findings(disasm_findings)
    assert len(funcs2) == 1
    fn2 = funcs2[0]
    assert fn2.is_verified_decompiler is False
    assert fn2.confidence_score < 1.0
    assert "[RECONSTRUCTED ANALYSIS - NOT ORIGINAL SOURCE CODE]" in fn2.pseudocode
    assert fn2.cyclomatic_complexity >= 2
    assert len(fn2.source_asm_map) >= 5
    assert fn2.source_asm_map[0]["address"] == "0x00401000"


def test_implementation_task_planner_and_human_review():
    findings = [
        Finding("binary", "lief", "header", "pe_header", {"format": "PE", "arch": "X86_64"}),
        Finding(
            "synthesizer",
            "reforge",
            "decompiled_synthesized",
            "calc_factorial",
            {"name": "calc_factorial", "address": "0x00401050", "cyclomatic_complexity": 3, "is_verified_decompiler": True},
        ),
        Finding(
            "synthesizer",
            "reforge",
            "decompiled_synthesized",
            "authenticate_user",
            {"name": "authenticate_user", "address": "0x00401150", "cyclomatic_complexity": 2, "is_verified_decompiler": False},
        ),
        Finding("network", "floss", "network", "url_0", ["https://api.ref.internal/v1/auth"]),
    ]

    spec = (
        "# Spec\n"
        "## 4. Inferred Behavioral Logic `[INFERRED BEHAVIOR - TENTATIVE]`\n"
        "## 6. Unknown Functionality `[UNKNOWN FUNCTIONALITY]`\n"
    )

    tasks, reviews = TaskPlanner.generate_plan(spec, findings, "ReferenceCalc", tech_stack="python")

    # Tasks check
    assert len(tasks) >= 4
    task_ids = [t.id for t in tasks]
    assert "TASK-01-ARCH" in task_ids
    assert any("CALC_FACTORIAL" in tid for tid in task_ids)
    assert any("AUTHENTICATE_USER" in tid for tid in task_ids)
    assert any("NET-CLIENT" in tid for tid in task_ids)

    # Acceptance criteria present
    for t in tasks:
        assert len(t.acceptance_criteria) >= 2
        assert t.category in ("architecture", "core_logic", "data_models", "interface_contract", "security_safety", "testing_validation")

    # Reviews check
    assert len(reviews) >= 2
    assert any(r.evidence_status == "UNVERIFIED_DATA" for r in reviews)
    assert any(r.evidence_status == "UNKNOWN_FUNCTIONALITY" for r in reviews)
    assert any("Independent Implementation Verification" in r.item for r in reviews)


def test_realistic_behavioral_tests_no_invented_endpoints():
    # Case 1: Pure offline CLI application with NO endpoints discovered
    tests_no_ep = generate_evidence_tests(
        stack="python",
        project_name="OfflineCLI",
        features=[{"name": "calc_add"}, {"name": "calc_factorial"}],
        endpoints=None,  # No endpoints!
        indicators=["CLI_VERBOSE"],
    )

    py_code = tests_no_ep["tests/test_behavioral.py"]
    # Must NOT invent default endpoints
    assert "/api/v1/status" not in py_code
    assert "/api/v1/health" not in py_code
    assert "test_verified_feature_calc_add" in py_code
    assert "test_verified_feature_calc_factorial" in py_code
    assert "Zero external endpoints were detected" in py_code

    # Syntax validation with local Python toolchain
    val = validate_generated_tests(tests_no_ep, stack="python")
    assert val["validated"] is True
    assert len(val["errors"]) == 0

    # Case 2: Multi-stack realistic test generation (TypeScript, Rust, Go, C#)
    for stack in ("typescript", "rust", "go", "csharp"):
        out = generate_evidence_tests(stack, "App", endpoints=[], indicators=[])
        assert len(out) == 1
        code = next(iter(out.values()))
        assert "/api/v1/status" not in code


def test_structural_binary_diffing_renamed_symbols_and_shifted_addresses():
    # Function A in version 1
    asm_a = [
        "0x00401000  55                   push rbp",
        "0x00401001  48 89 e5             mov rbp, rsp",
        "0x00401004  89 7d fc             mov [rbp - 4], edi",
        "0x00401007  8b 45 fc             mov eax, [rbp - 4]",
        "0x0040100a  83 c0 2a             add eax, 42",
        "0x0040100d  5d                   pop rbp",
        "0x0040100e  c3                   ret",
    ]

    # Function B in version 2: Renamed to 'sub_402500' AND address shifted to 0x00402500
    asm_b = [
        "0x00402500  55                   push rbp",
        "0x00402501  48 89 e5             mov rbp, rsp",
        "0x00402504  89 7d f8             mov [rbp - 8], edi",
        "0x00402507  8b 45 f8             mov eax, [rbp - 8]",
        "0x0040250a  83 c0 2a             add eax, 42",
        "0x0040250d  5d                   pop rbp",
        "0x0040250e  c3                   ret",
    ]

    fn_a = DecompiledFunction(
        name="calculate_offset",
        address="0x00401000",
        assembly_lines=asm_a,
        pseudocode="int calculate_offset(int x) { return x + 42; }",
    )

    fn_b = DecompiledFunction(
        name="sub_402500",  # Renamed!
        address="0x00402500",  # Shifted!
        assembly_lines=asm_b,
        pseudocode="int sub_402500(int x) { return x + 42; }",
    )

    diff = BinaryDiffEngine.compare_findings(
        findings_a=[Finding("synthesizer", "reforge", "decompiled_synthesized", fn_a.name, fn_a.to_dict())],
        findings_b=[Finding("synthesizer", "reforge", "decompiled_synthesized", fn_b.name, fn_b.to_dict())],
        name_a="v1.0",
        name_b="v2.0",
    )

    assert len(diff.functions) == 1
    matched_item = diff.functions[0]
    # Structural matcher matched them despite renamed symbol and relocated address!
    assert "calculate_offset" in matched_item.name
    assert "sub_402500" in matched_item.name
    assert matched_item.match_type in ("structural_match", "uncertain_match")
    assert matched_item.confidence >= 0.70
    assert "Normalized mnemonics" in matched_item.match_reason


def test_tag_release_immutability_protection(monkeypatch):
    from scripts import autopilot

    # Mock local tag already exists
    monkeypatch.setattr(autopilot, "run_cmd", lambda cmd: (0, "v0.7.0") if cmd == ["git", "tag", "-l", "v0.7.0"] else (0, "main"))
    monkeypatch.setattr(autopilot, "get_current_version", lambda: "0.7.0")

    ok = autopilot.tag_release("0.7.0", push=False, force_skip_ci=True)
    assert ok is False


def test_reconstruction_page_tasks_and_reviews_ui(db, samples, qapp):
    win = MainWindow()
    win.ctx.db = db

    pid = db.create_project("Ref Target", str(samples["apk"]), "standard")
    db.add_findings(
        pid,
        [
            Finding("synthesizer", "reforge", "decompiled_synthesized", "calc_add", {"name": "calc_add", "address": "0x401000"}),
            Finding("network", "floss", "network", "api", ["https://api.ref.internal/v1"]),
        ],
    )

    page = win.pages["Reconstruction Studio"]
    page.refresh(select=pid)

    # Wizard tabs has 4 tabs
    assert page.wizard_tabs.count() == 4
    assert page.wizard_tabs.tabText(3) == "4. Tasks & Review"

    # Tasks and reviews tables populated
    assert page.table_tasks.rowCount() >= 2
    assert page.table_reviews.rowCount() >= 2

    # Verify task columns
    first_task_id = page.table_tasks.item(0, 0).text()
    assert first_task_id.startswith("TASK-")

    # Verify review item
    first_rev_id = page.table_reviews.item(0, 0).text()
    assert first_rev_id.startswith("REV-")

    win.close()
