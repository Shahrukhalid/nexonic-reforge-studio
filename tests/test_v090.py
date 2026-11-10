"""Unit and integration tests for Milestone v0.9.0.

Covers:
- Control Flow Graph (CFG) extraction, modeling, cyclomatic complexity, loop detection, DOT, and ASCII diagrams.
- Interactive CFGVisualizerWidget PySide6 component.
- Multi-engine decompilation orchestration and comparison.
- Host compiler toolchain discovery.
- Reconstructed project scaffolding for C/C++, Java, and C#.
- Build and runner configuration detection for all supported stacks.
- Application Explorer CFG and decompiler engine integration.
"""
from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from reforge.analysis.cfg import (
    CFGGraph,
    build_cfg_from_assembly,
    build_cfg_from_blocks,
)
from reforge.analysis.decompiler_orchestrator import (
    DecompilerEngine,
    DecompilerOrchestrator,
)
from reforge.core.db import Database
from reforge.core.findings import Confidence, Finding, Provenance
from reforge.reconstruct.builder import (
    build_reconstructed_project,
    detect_build_configuration,
)
from reforge.reconstruct.runner import detect_runner_commands
from reforge.reconstruct.scaffold import scaffold_project
from reforge.reconstruct.toolchains import detect_host_toolchains
from reforge.ui.pages.explorer_page import ApplicationExplorerPage
from reforge.ui.widgets.cfg_view import CFGVisualizerWidget


@pytest.fixture
def sample_blocks():
    return [
        {
            "id": "loc_0x1000",
            "start_addr": "0x1000",
            "end_addr": "0x100c",
            "instructions": ["0x1000: push rbp", "0x1004: mov rbp, rsp", "0x1008: cmp edi, 0", "0x100c: jle 0x1020"],
            "successors": ["loc_0x1010", "loc_0x1020"],
            "edges": [
                {"source_block": "loc_0x1000", "target_block": "loc_0x1010", "edge_type": "conditional_false"},
                {"source_block": "loc_0x1000", "target_block": "loc_0x1020", "edge_type": "conditional_true"},
            ],
        },
        {
            "id": "loc_0x1010",
            "start_addr": "0x1010",
            "end_addr": "0x1018",
            "instructions": ["0x1010: add eax, edi", "0x1014: dec edi", "0x1018: jmp 0x1008"],
            "successors": ["loc_0x1000"],
            "edges": [
                {"source_block": "loc_0x1010", "target_block": "loc_0x1000", "edge_type": "unconditional"},
            ],
        },
        {
            "id": "loc_0x1020",
            "start_addr": "0x1020",
            "end_addr": "0x1024",
            "instructions": ["0x1020: pop rbp", "0x1024: ret"],
            "successors": [],
            "edges": [],
        },
    ]


def test_cfg_graph_extraction_and_metrics(sample_blocks):
    graph = build_cfg_from_blocks(sample_blocks, function_name="calc_sum", entry_addr="0x1000", arch="x86-64")
    assert isinstance(graph, CFGGraph)
    assert graph.function_name == "calc_sum"
    assert len(graph.nodes) == 3
    assert len(graph.edges) == 3

    # Cyclomatic complexity M = E - N + 2 = 3 - 3 + 2 = 2
    assert graph.cyclomatic_complexity == 2

    # Loop detection: loc_0x1010 -> loc_0x1000 forms a cycle/back-edge
    assert graph.loop_count >= 1
    assert graph.nodes["loc_0x1000"].is_loop_head

    # DOT serialization
    dot = graph.to_dot()
    assert "digraph \"CFG_calc_sum\"" in dot
    assert "loc_0x1000" in dot
    assert "loc_0x1010" in dot
    assert "loc_0x1020" in dot

    # ASCII diagram
    ascii_diag = graph.to_ascii_diagram()
    assert "CONTROL FLOW GRAPH: calc_sum" in ascii_diag
    assert "[LOOP-HEAD]" in ascii_diag
    assert "[TERMINAL RETURN / STOP]" in ascii_diag


def test_cfg_from_assembly():
    asm = [
        "0x401000: mov eax, 1",
        "0x401005: cmp eax, 5",
        "0x401008: jge 0x401015",
        "0x40100a: inc eax",
        "0x40100d: jmp 0x401005",
        "0x401015: ret",
    ]
    graph = build_cfg_from_assembly(asm, function_name="test_loop", arch="x86-64", entry_addr="0x401000")
    assert graph.function_name == "test_loop"
    assert len(graph.nodes) >= 2
    assert graph.cyclomatic_complexity >= 2
    assert graph.loop_count >= 1


def test_cfg_visualizer_widget(qapp, sample_blocks):
    widget = CFGVisualizerWidget()
    graph = build_cfg_from_blocks(sample_blocks, function_name="calc_sum", entry_addr="0x1000")
    widget.load_graph(graph)

    assert "calc_sum" in widget.lbl_info.text()
    assert len(widget.cards) == 3

    # Test filter
    widget._apply_filter("ret")
    assert not widget.cards["loc_0x1020"].isHidden()
    assert widget.cards["loc_0x1010"].isHidden()

    # Test mode toggle
    widget.view_mode_sel.setCurrentText("ASCII / Unicode Flow")
    assert not widget.text_view.isHidden()
    assert "CONTROL FLOW GRAPH" in widget.text_view.toPlainText()

    widget.view_mode_sel.setCurrentText("Graphviz DOT")
    assert not widget.text_view.isHidden()
    assert "digraph" in widget.text_view.toPlainText()

    # Signal emission
    received = []
    widget.block_selected.connect(lambda addr: received.append(addr))
    widget._on_card_clicked("loc_0x1000")
    assert len(received) == 1
    assert received[0] == "0x1000"

    widget.clear()
    assert widget.current_graph is None


def test_decompiler_orchestrator():
    engines = DecompilerOrchestrator.get_supported_engines()
    assert len(engines) >= 4
    engine_ids = [e["id"] for e in engines]
    assert DecompilerEngine.GHIDRA.value in engine_ids
    assert DecompilerEngine.JADX.value in engine_ids
    assert DecompilerEngine.ILSPY.value in engine_ids
    assert DecompilerEngine.SYNTHESIZER.value in engine_ids

    # Best engine resolution
    assert DecompilerOrchestrator.resolve_best_engine("apk", ["jadx", "synthesizer"]) == "jadx"
    assert DecompilerOrchestrator.resolve_best_engine(".net", ["ilspy", "synthesizer"]) == "ilspy"
    assert DecompilerOrchestrator.resolve_best_engine("pe", ["ghidra", "synthesizer"]) == "ghidra"
    assert DecompilerOrchestrator.resolve_best_engine("pe", ["synthesizer"]) == "synthesizer"

    # Extraction from findings
    findings = [
        Finding(
            stage="tools",
            tool="ghidra",
            kind="decompiled",
            key="calc_add",
            value={"entry": "0x1000", "code": "int calc_add(int a, int b) { return a + b; }", "arch": "x86-64"},
            confidence=Confidence.CONFIRMED,
            provenance=Provenance.DECOMPILED,
        ),
        Finding(
            stage="tools",
            tool="jadx",
            kind="decompiled",
            key="AuthService.java",
            value={"code": "public class AuthService { public boolean login() { return true; } }"},
            confidence=Confidence.CONFIRMED,
            provenance=Provenance.DECOMPILED,
        ),
    ]

    outputs = DecompilerOrchestrator.extract_engine_outputs(findings)
    assert "calc_add" in outputs["ghidra"]
    assert "AuthService.java" in outputs["jadx"]
    assert outputs["ghidra"]["calc_add"].is_genuine

    # Compare decompiler outputs
    cmp_res = DecompilerOrchestrator.compare_decompiler_outputs("calc_add", "ghidra", "synthesizer", outputs)
    assert cmp_res["function"] == "calc_add"
    assert "int calc_add" in cmp_res["code_a"]


def test_host_toolchains_discovery():
    toolchains = detect_host_toolchains(force_refresh=True)
    assert "python" in toolchains
    # Python must be available since we are running tests
    py_tc = toolchains["python"]
    assert py_tc.available
    assert py_tc.version != ""

    # Verify toolchain definitions
    for tid in ["cargo", "go", "dotnet", "javac", "cmake"]:
        assert tid in toolchains
        assert toolchains[tid].category in ("compiler", "runtime", "build_system", "package_manager")
        assert len(toolchains[tid].supported_targets) > 0


def test_scaffold_multi_stack():
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)

        # 1. C/C++ project
        c_dir = tmp_path / "c_proj"
        c_files = scaffold_project(c_dir, project_name="CalcService", stack="c")
        assert "CMakeLists.txt" in c_files
        assert "include/core.h" in c_files
        assert "src/core.c" in c_files
        assert "tests/test_core.c" in c_files
        assert (c_dir / "CMakeLists.txt").is_file()

        # 2. Java project
        java_dir = tmp_path / "java_proj"
        java_files = scaffold_project(java_dir, project_name="OrderService", stack="java")
        assert "pom.xml" in java_files
        assert "src/main/java/com/reforge/cleanroom/App.java" in java_files
        assert (java_dir / "pom.xml").is_file()

        # 3. C# project
        cs_dir = tmp_path / "cs_proj"
        cs_files = scaffold_project(cs_dir, project_name="BillingService", stack="csharp")
        assert any(k.endswith(".csproj") for k in cs_files)
        assert "src/Program.cs" in cs_files
        assert any(cs_dir.glob("*.csproj"))


def test_builder_and_runner_multi_stack():
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)

        # C project detection
        c_dir = tmp_path / "c_app"
        scaffold_project(c_dir, "CApp", stack="c")
        cfg_c = detect_build_configuration(c_dir)
        assert cfg_c["language"] == "c"
        cmds_c = detect_runner_commands(c_dir)
        assert "build" in cmds_c

        # Java project detection
        j_dir = tmp_path / "j_app"
        scaffold_project(j_dir, "JavaApp", stack="java")
        cfg_j = detect_build_configuration(j_dir)
        assert cfg_j["language"] == "java"
        cmds_j = detect_runner_commands(j_dir)
        assert "test" in cmds_j

        # C# project detection
        cs_dir = tmp_path / "cs_app"
        scaffold_project(cs_dir, "CsApp", stack="csharp")
        cfg_cs = detect_build_configuration(cs_dir)
        assert cfg_cs["language"] == "csharp"
        cmds_cs = detect_runner_commands(cs_dir)
        assert "build" in cmds_cs

        # Python project compilation test
        py_dir = tmp_path / "py_app"
        scaffold_project(py_dir, "PyApp", stack="python")
        cfg_py = detect_build_configuration(py_dir)
        assert cfg_py["language"] == "python"

        # Build python wheel package
        dist_dir = py_dir / "dist"
        res = build_reconstructed_project(py_dir, output_dir=dist_dir, target="package", timeout=30)
        assert res.output_dir == dist_dir
        assert (dist_dir / "build_manifest.json").is_file()


def test_ui_explorer_cfg_and_engine_integration(qapp):
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        db_path = tmp_path / "test.db"
        db = Database(db_path)
        pid = db.create_project("test_app", "pe", str(tmp_path))

        db.add_findings(pid, [
            Finding(
                stage="tools",
                tool="ghidra",
                kind="decompiled",
                key="process_data",
                value={
                    "entry": "0x401000",
                    "code": "int process_data(int x) { return x * 2; }",
                    "cfg_blocks": [
                        {
                            "id": "block_0",
                            "start_addr": "0x401000",
                            "end_addr": "0x40100a",
                            "instructions": ["0x401000: mov eax, edi", "0x401002: shl eax, 1", "0x401004: ret"],
                            "successors": [],
                        }
                    ],
                },
                confidence=Confidence.CONFIRMED,
                provenance=Provenance.DECOMPILED,
            ),
        ])

        class DummyCtx:
            def __init__(self):
                self.db = db
                self.theme = "dark"
                self.status_messages = []

            def status(self, msg):
                self.status_messages.append(msg)

        ctx = DummyCtx()
        try:
            page = ApplicationExplorerPage(ctx)
            page.refresh(select=pid)

            # Trigger item display
            finding = db.findings(pid)[0]
            page._display_finding(finding)

            # Verify CFG widget received blocks
            assert page.cfg_widget.current_graph is not None
            assert page.cfg_widget.current_graph.function_name == "process_data"
            assert len(page.cfg_widget.cards) == 1

            # Test engine selection change
            page.engine_sel.setCurrentText("Ghidra")
            assert "process_data" in page.code_edit.toPlainText()

            # Test CFG block selection navigates code
            page._on_cfg_block_selected("0x401000")
            assert page.view_tabs.currentIndex() == 0
        finally:
            db.close()
