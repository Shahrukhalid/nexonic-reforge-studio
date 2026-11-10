"""Milestone v0.7.0 tests: release gate fail-closed, decompilation synthesizer, binary diffing, evidence-based tests."""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from reforge.analysis.diffing import BinaryDiffEngine
from reforge.analysis.synthesizer import DecompilationSynthesizer, DecompiledFunction
from reforge.core.findings import Finding
from reforge.reconstruct.scaffold import (
    generate_specification,
    get_license_text,
)
from reforge.reconstruct.tests_gen import generate_evidence_tests
from reforge.ui.main_window import MainWindow
from reforge.ui.pages.explorer_page import ApplicationExplorerPage


def test_release_gate_fail_closed_logic(monkeypatch):
    from scripts.autopilot import REQUIRED_CI_CHECKS, check_ci_status

    # Mock 1: Missing checks should fail closed
    incomplete_runs = {
        "check_runs": [
            {"name": "test (ubuntu-24.04)", "status": "completed", "conclusion": "success"},
            {"name": "test (windows-2022)", "status": "completed", "conclusion": "success"},
        ]
    }
    monkeypatch.setattr("scripts.autopilot.github_request", lambda url: incomplete_runs)
    ok, statuses = check_ci_status("dummy_sha")
    assert not ok
    assert len(statuses) < len(REQUIRED_CI_CHECKS)

    # Mock 2: Non-success conclusion (e.g. failure, cancelled, skipped) should fail closed
    failed_runs = {
        "check_runs": [
            {"name": req, "status": "completed", "conclusion": "success" if req != "audit" else "failure"}
            for req in REQUIRED_CI_CHECKS
        ]
    }
    monkeypatch.setattr("scripts.autopilot.github_request", lambda url: failed_runs)
    ok, statuses = check_ci_status("dummy_sha")
    assert not ok

    # Mock 3: All 7 required checks present, completed, and success should pass
    success_runs = {
        "check_runs": [
            {"name": req, "status": "completed", "conclusion": "success"}
            for req in REQUIRED_CI_CHECKS
        ]
    }
    monkeypatch.setattr("scripts.autopilot.github_request", lambda url: success_runs)
    ok, statuses = check_ci_status("dummy_sha")
    assert ok


def test_license_templates_full_text():
    assert "Permission is hereby granted, free of charge" in get_license_text("MIT")
    assert "TERMS AND CONDITIONS FOR USE, REPRODUCTION" in get_license_text("Apache-2.0")
    assert "Redistribution and use in source and binary forms" in get_license_text("BSD-3-Clause")
    assert "CONFIDENTIAL AND PROPRIETARY SOFTWARE" in get_license_text("Proprietary")


def test_specification_distinction_categories():
    findings = [
        {
            "stage": "binary",
            "key": "pe_header",
            "value": {
                "format": "PE",
                "arch": "X86_64",
                "bits": 64,
                "endianness": "little",
                "pie": True,
                "nx": True,
            },
        },
        {"stage": "binary", "key": "libraries", "value": ["KERNEL32.dll", "ADVAPI32.dll"]},
        {"stage": "analysis", "kind": "network", "value": ["https://auth.internal/v1", "10.0.0.1"]},
        {"stage": "analysis", "kind": "indicators", "value": ["LOG_LEVEL", "DEBUG_ENABLED"]},
    ]

    spec = generate_specification(findings, "TestApp")
    assert "## 2. Observed Binary Facts & Platform Constraints `[OBSERVED FACT - CONFIRMED]`" in spec
    assert "KERNEL32.dll" in spec
    assert "## 4. Inferred Behavioral Logic & Control Flow `[INFERRED BEHAVIOR - TENTATIVE]`" in spec
    assert "## 5. Unverified Network Endpoints & Protocol Indicators `[UNVERIFIED DATA - REQUIRES VALIDATION]`" in spec
    assert "https://auth.internal/v1" in spec
    assert "## 6. Unknown Functionality & Analysis Boundaries `[UNKNOWN FUNCTIONALITY]`" in spec


def test_decompilation_synthesizer_pseudocode_and_cfg():
    asm_lines = [
        "0x00401000  55                   push rbp",
        "0x00401001  48 89 e5             mov rbp, rsp",
        "0x00401004  48 83 ec 10          sub rsp, 0x10",
        "0x00401008  e8 23 01 00 00       call 0x00401130",
        "0x0040100d  85 c0                test eax, eax",
        "0x0040100f  75 05                jne 0x00401016",
        "0x00401011  b8 00 00 00 00       mov eax, 0",
        "0x00401016  c9                   leave",
        "0x00401017  c3                   ret",
    ]

    findings = [
        Finding(
            stage="disasm",
            tool="capstone",
            kind="disassembly",
            key="export:calculate_checksum",
            value={"arch": "x86-64", "address": "0x00401000", "lines": asm_lines},
        )
    ]

    funcs = DecompilationSynthesizer.synthesize_from_findings(findings, "sample.exe")
    assert len(funcs) == 1
    fn = funcs[0]
    assert fn.name == "calculate_checksum"
    assert fn.address == "0x00401000"
    assert "[RECONSTRUCTED ANALYSIS - NOT ORIGINAL SOURCE CODE]" in fn.pseudocode
    assert "/* 0x00401008 */  result = 0x00401130();" in fn.pseudocode
    assert "/* 0x0040100f */  if (condition_ne(flags)) goto 0x00401016;" in fn.pseudocode
    assert len(fn.cfg_blocks) >= 2


def test_binary_diff_engine_comparison():
    fn_a = DecompiledFunction(
        name="authenticate",
        address="0x00401000",
        assembly_lines=["mov eax, 1", "ret"],
        pseudocode="int authenticate() { return 1; }",
    )
    fn_b = DecompiledFunction(
        name="authenticate",
        address="0x00401000",
        assembly_lines=["mov eax, 0", "ret"],
        pseudocode="int authenticate() { return 0; }",
    )
    fn_added = DecompiledFunction(
        name="new_feature",
        address="0x00402000",
        assembly_lines=["ret"],
        pseudocode="void new_feature() {}",
    )

    findings_a = [
        Finding("synthesizer", "reforge", "decompiled_synthesized", fn_a.name, fn_a.to_dict()),
        Finding("binary", "lief", "imports", "libraries", ["libssl.so"]),
    ]
    findings_b = [
        Finding("synthesizer", "reforge", "decompiled_synthesized", fn_b.name, fn_b.to_dict()),
        Finding("synthesizer", "reforge", "decompiled_synthesized", fn_added.name, fn_added.to_dict()),
        Finding("binary", "lief", "imports", "libraries", ["libssl.so", "libcrypto.so"]),
    ]

    diff = BinaryDiffEngine.compare_findings(findings_a, findings_b, "v1.0", "v2.0")

    assert diff.summary["modified"] == 1
    assert diff.summary["added"] == 1
    assert "libcrypto.so" in diff.imports_diff["added"]

    report_md = BinaryDiffEngine.generate_diff_report(diff, format="markdown")
    assert "# Nexonic ReForge Studio — Binary Comparison Report" in report_md
    assert "new_feature" in report_md

    report_json = BinaryDiffEngine.generate_diff_report(diff, format="json")
    data = json.loads(report_json)
    assert data["target_a"] == "v1.0"
    assert data["target_b"] == "v2.0"


def test_evidence_based_test_generation_multi_stack():
    # Python
    py_tests = generate_evidence_tests("python", "App")
    assert "tests/test_behavioral.py" in py_tests
    assert "[VERIFIED CONTRACT]" in py_tests["tests/test_behavioral.py"]
    assert "[BEHAVIORAL MOCK]" in py_tests["tests/test_behavioral.py"]

    # TypeScript
    ts_tests = generate_evidence_tests("typescript", "App")
    assert "tests/behavioral.test.js" in ts_tests

    # Rust
    rs_tests = generate_evidence_tests("rust", "App")
    assert "tests/behavioral_test.rs" in rs_tests

    # Go
    go_tests = generate_evidence_tests("go", "App")
    assert "behavioral_test.go" in go_tests

    # C#
    cs_tests = generate_evidence_tests("csharp", "App")
    assert "tests/BehavioralTests.cs" in cs_tests


def test_explorer_page_binary_diff_and_views(db, samples, qapp):
    win = MainWindow()
    win.ctx.db = db

    pid1 = db.create_project("Target A", str(samples["apk"]), "standard")
    pid2 = db.create_project("Target B", str(samples["jar"]), "standard")

    explorer = ApplicationExplorerPage(win.ctx)
    explorer.refresh(select=pid1)

    assert explorer.tabs.count() >= 6
    assert explorer.tabs.tabText(5) == "Binary Diff"

    # Select target B and trigger binary diff
    target_b_idx = -1
    for i in range(explorer.diff_proj_sel.count()):
        if explorer.diff_proj_sel.itemData(i) == pid2:
            target_b_idx = i
            break
    assert target_b_idx >= 0
    explorer.diff_proj_sel.setCurrentIndex(target_b_idx)
    explorer._on_run_binary_diff()

    assert explorer.current_diff_result is not None
    assert explorer.diff_table.rowCount() >= 0
