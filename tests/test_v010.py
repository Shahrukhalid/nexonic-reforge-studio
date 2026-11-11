"""Comprehensive test suite for Milestone v0.10.0 Production Readiness & Real-World Validation."""
from __future__ import annotations

from pathlib import Path

from reforge.analysis.benchmark_targets import (
    get_ground_truth_specs,
    run_ground_truth_benchmark_for_fixture,
)
from reforge.analysis.cfg import (
    CFGDirectedEdge,
    CFGNode,
    build_cfg_from_blocks,
    compute_cfg_dominance,
    is_indirect_instruction,
)
from reforge.reconstruct.builder import build_reconstructed_project
from reforge.reconstruct.isolation import verify_cleanroom_isolation
from reforge.reconstruct.runner import parse_test_summary
from reforge.reconstruct.scaffold import scaffold_project


def test_formal_dominator_tree_and_natural_loops():
    """Verify formal dominator tree, immediate dominator (idom), dominance frontier, and natural loops."""
    # Graph structure:
    # bb_entry -> bb_loop_head -> bb_body -> bb_latch -> bb_loop_head (back-edge)
    # bb_loop_head -> bb_exit
    # bb_unreachable (isolated)
    nodes = {
        "entry": CFGNode(id="entry", start_addr="0x1000", end_addr="0x1008", is_entry=True, successors=["head"]),
        "head": CFGNode(id="head", start_addr="0x1010", end_addr="0x1018", successors=["body", "exit"]),
        "body": CFGNode(id="body", start_addr="0x1020", end_addr="0x1028", successors=["latch"]),
        "latch": CFGNode(id="latch", start_addr="0x1030", end_addr="0x1038", successors=["head"]),
        "exit": CFGNode(id="exit", start_addr="0x1040", end_addr="0x1048", is_exit=True, successors=[]),
        "unreachable": CFGNode(id="unreachable", start_addr="0x2000", end_addr="0x2008", successors=[]),
    }

    edges = [
        CFGDirectedEdge(source="entry", target="head", edge_type="unconditional"),
        CFGDirectedEdge(source="head", target="body", edge_type="conditional_true"),
        CFGDirectedEdge(source="head", target="exit", edge_type="conditional_false"),
        CFGDirectedEdge(source="body", target="latch", edge_type="unconditional"),
        CFGDirectedEdge(source="latch", target="head", edge_type="unconditional"),
    ]

    for e in edges:
        if e.target in nodes:
            nodes[e.target].predecessors.append(e.source)

    doms, idoms, dfs, natural_loops, unreachable = compute_cfg_dominance(nodes, edges, "entry")

    # Entry dominates everything reachable
    assert "entry" in doms["head"]
    assert "entry" in doms["body"]
    assert "entry" in doms["exit"]

    # Head dominates body, latch, and exit
    assert "head" in doms["body"]
    assert "head" in doms["latch"]
    assert "head" in doms["exit"]

    # Immediate dominators
    assert idoms["entry"] is None
    assert idoms["head"] == "entry"
    assert idoms["body"] == "head"
    assert idoms["latch"] == "body"
    assert idoms["exit"] == "head"

    # Natural loop: header='head', latch='latch', body contains {head, body, latch}
    assert len(natural_loops) == 1
    nl = natural_loops[0]
    assert nl.header == "head"
    assert nl.latch == "latch"
    assert set(nl.blocks) == {"head", "body", "latch"}

    # Unreachable block correctly detected
    assert "unreachable" in unreachable
    assert nodes["unreachable"].is_unreachable is True


def test_indirect_branch_detection():
    """Verify indirect branch detection for x86 and ARM instruction patterns."""
    assert is_indirect_instruction("jmp rax") is True
    assert is_indirect_instruction("0x401000: jmp qword ptr [rbx+rcx*8]") is True
    assert is_indirect_instruction("call rdx") is True
    assert is_indirect_instruction("bx r3") is True
    assert is_indirect_instruction("br x0") is True

    # Direct jumps should be False
    assert is_indirect_instruction("jmp 0x401050") is False
    assert is_indirect_instruction("call loc_func_42") is False
    assert is_indirect_instruction("add rax, rbx") is False


def test_cfg_graph_serialization_and_dot():
    """Verify CFG graph serialization, JSON export, DOT export, and ASCII rendering."""
    blocks = [
        {
            "id": "bb_0",
            "start_addr": "0x1000",
            "end_addr": "0x100a",
            "instructions": ["0x1000: mov rax, [rbp-8]", "0x1008: jmp rax"],
            "successors": ["bb_1"],
        },
        {
            "id": "bb_1",
            "start_addr": "0x1010",
            "end_addr": "0x1015",
            "instructions": ["0x1010: ret"],
            "successors": [],
        },
    ]

    graph = build_cfg_from_blocks(blocks, "indirect_test", "0x1000")
    assert graph.function_name == "indirect_test"
    assert "bb_0" in graph.nodes
    assert graph.nodes["bb_0"].has_indirect_branch is True

    dot = graph.to_dot()
    assert 'digraph "CFG_indirect_test"' in dot
    assert "INDIRECT" in dot

    ascii_diag = graph.to_ascii_diagram()
    assert "CONTROL FLOW GRAPH: indirect_test" in ascii_diag

    d = graph.to_dict()
    assert "dominators" in d
    assert "immediate_dominators" in d
    assert "natural_loops" in d


def test_reference_target_fixtures_and_ground_truth(tmp_path):
    """Verify ground-truth benchmarking on authorized reference fixtures."""
    fixtures_dir = Path(__file__).resolve().parent / "fixtures" / "reference"
    out_dir = tmp_path / "benchmarks"

    specs = get_ground_truth_specs()
    assert len(specs) >= 7

    # Run benchmark on C reference fixture
    c_fixture = fixtures_dir / "reference_calc.c"
    if c_fixture.exists():
        res = run_ground_truth_benchmark_for_fixture("c_calc", c_fixture, out_dir / "c_calc")
        assert res.target_name == "reference_calc"
        if res.compilation_succeeded:
            assert res.report is not None and res.report.overall_accuracy > 0.0
            assert len(res.report.verified_recovered_items) > 0
        else:
            assert res.status in ("skipped_missing_toolchain", "failed_compilation")

    # Run benchmark on Go reference fixture
    go_fixture = fixtures_dir / "reference_service.go"
    if go_fixture.exists():
        res = run_ground_truth_benchmark_for_fixture("go_service", go_fixture, out_dir / "go_service")
        assert res.target_name == "reference_service"
        if res.compilation_succeeded:
            assert res.report is not None and res.report.overall_accuracy > 0.0
        else:
            assert res.status in ("skipped_missing_toolchain", "failed_compilation")

    # Run benchmark on Python reference fixture
    py_fixture = fixtures_dir / "reference_app.py"
    if py_fixture.exists():
        res = run_ground_truth_benchmark_for_fixture("py_app", py_fixture, out_dir / "py_app")
        assert res.target_name == "reference_app"
        assert res.compilation_succeeded is True
        assert res.compiled_binary is not None and res.compiled_binary.endswith(".pyc")
        assert res.report is not None and res.report.overall_accuracy > 0.0


def test_clean_room_isolation_auditor(tmp_path):
    """Verify clean-room isolation verification detects leaks and certifies clean trees."""
    extracted_dir = tmp_path / "extracted"
    extracted_dir.mkdir(parents=True, exist_ok=True)

    # 1. Create original extracted application files
    (extracted_dir / "proprietary_core.bin").write_bytes(b"\x7fELF" + b"A" * 500)
    (extracted_dir / "secret_algo.c").write_text(
        "/* CONFIDENTIAL AND PROPRIETARY */\nint secret_val = 0x9922;\n" + "x" * 200,
        encoding="utf-8",
    )

    # 2. Test dirty reconstructed directory with leaked binary
    dirty_recon = tmp_path / "dirty_recon"
    dirty_recon.mkdir(parents=True, exist_ok=True)
    (dirty_recon / "leaked_core.bin").write_bytes(b"\x7fELF" + b"A" * 500)
    (dirty_recon / "dirty_code.c").write_text(
        "/* CONFIDENTIAL AND PROPRIETARY */\nint clean_code = 1;\n",
        encoding="utf-8",
    )

    dirty_res = verify_cleanroom_isolation(extracted_dir, dirty_recon)
    assert dirty_res.is_clean is False
    assert dirty_res.violation_count >= 2
    assert any("Binary artifact" in v for v in dirty_res.violations)
    assert any("proprietary marker" in v for v in dirty_res.violations)

    # 3. Test clean reconstructed directory
    clean_recon = tmp_path / "clean_recon"
    scaffold_project(
        clean_recon,
        "CleanApp",
        "python",
        ["Calculations", "Authentication"],
        "# Independent Clean Room Specification\n",
    )

    clean_res = verify_cleanroom_isolation(extracted_dir, clean_recon)
    assert clean_res.is_clean is True
    assert clean_res.violation_count == 0
    assert clean_res.clean_ratio == 1.0


def test_build_pipeline_strict_failure_handling(tmp_path):
    """Verify builder strictly marks failed builds as success=False and does not produce artifacts."""
    bogus_project = tmp_path / "bogus_py"
    bogus_project.mkdir(parents=True, exist_ok=True)
    # Python project with syntax error in entry point
    (bogus_project / "main.py").write_text("def broken_syntax(:\n", encoding="utf-8")

    dist = bogus_project / "dist"
    # Create a pre-existing stale file in dist to ensure it is not counted on failure
    dist.mkdir(parents=True, exist_ok=True)
    stale_file = dist / "bogus_py.exe"
    stale_file.write_text("stale", encoding="utf-8")

    res = build_reconstructed_project(bogus_project, target="binary", output_dir=dist)
    assert res.success is False
    assert len(res.artifacts) == 0
    # Stale file should be cleaned up
    assert not stale_file.exists()


def test_runner_summary_parsing():
    """Verify test summary parser correctly extracts passed, failed, and skipped counts."""
    # Pytest output
    pytest_out = "===== 12 passed, 2 failed, 1 skipped in 1.45s ====="
    summary = parse_test_summary(pytest_out, "", 1, 1.45)
    assert summary.ok is False
    assert summary.passed == 12
    assert summary.failed == 2
    assert summary.skipped == 1
    assert summary.total == 15

    # Cargo output
    cargo_out = "test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out"
    summary_cargo = parse_test_summary(cargo_out, "", 0, 0.85)
    assert summary_cargo.ok is True
    assert summary_cargo.passed == 5
    assert summary_cargo.failed == 0
    assert summary_cargo.total == 5

    # .NET output
    net_out = "Passed!  - Failed:     0, Passed:     8, Skipped:     0, Total:     8, Duration: 23 ms"
    summary_net = parse_test_summary(net_out, "", 0, 0.5)
    assert summary_net.ok is True
    assert summary_net.passed == 8
    assert summary_net.failed == 0
    assert summary_net.total == 8
