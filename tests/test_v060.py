"""Milestone 0.6.0 tests: Assembly Highlighting, In-Line Search, Call Graph XREFs, and Multi-Module Reconstruction."""
from __future__ import annotations

from PySide6.QtGui import QTextDocument

from reforge.analysis.orchestrator import Orchestrator
from reforge.reconstruct import run_project_tests, scaffold_project
from reforge.reconstruct.scaffold import generate_specification
from reforge.ui.highlighter import CodeHighlighter
from reforge.ui.main_window import MainWindow


def test_highlighter_assembly_and_json():
    # 1. Assembly
    doc_asm = QTextDocument("0x00401000  48 89 df  mov rdi, rbx ; save ptr\n0x00401003  e8 10 00  call 0x401016\nret")
    hl_asm = CodeHighlighter(doc_asm, lang="asm", theme="dark")
    assert hl_asm.lang == "asm"
    assert len(hl_asm.rules) > 5

    # 2. JSON
    doc_json = QTextDocument('{\n  "version": "1.0",\n  "status": true,\n  "count": 42\n}')
    hl_json = CodeHighlighter(doc_json, lang="json", theme="dark")
    assert hl_json.lang == "json"
    assert len(hl_json.rules) >= 4


def test_analysis_page_find_and_highlight(db, samples, qapp):
    win = MainWindow()
    win.ctx.db = db
    pid = db.create_project("test_find_proj", str(samples["apk"]), "standard")
    Orchestrator(db).analyze(pid)

    page = win.pages["Analysis Workspace"]
    page.refresh(select=pid)
    assert page.tree.topLevelItemCount() > 0

    # Ensure a finding is selected and displayed
    first_item = page.tree.topLevelItem(0).child(0) if page.tree.topLevelItem(0).childCount() else page.tree.topLevelItem(0)
    page.tree.setCurrentItem(first_item)
    assert page.detail.toPlainText() != ""

    # Open find bar
    page._open_find_bar()
    assert not page.find_bar.isHidden()

    # Search for common term (e.g., "tool" or "file" in head)
    page.find_input.setText("tool")
    assert "match" in page.lbl_find_count.text()
    assert len(page.detail.extraSelections()) > 0

    # Next / previous navigation
    page._find_next(forward=True)
    page._find_next(forward=False)

    # Close find bar
    page._close_find_bar()
    assert page.find_bar.isHidden()
    assert len(page.detail.extraSelections()) == 0

    win.close()


def test_explorer_callgraph_deep_extraction(qapp):
    from reforge.ui.pages.explorer_page import ApplicationExplorerPage

    class DummyContext:
        theme = "dark"
        db = None

    page = ApplicationExplorerPage(DummyContext())

    mock_rows = [
        {
            "id": 1,
            "stage": "disasm",
            "tool": "capstone",
            "kind": "disassembly",
            "key": "entrypoint",
            "value": {
                "arch": "x86-64",
                "address": "0x401000",
                "lines": [
                    "0x000000401000  48 83 ec 28          sub rsp, 0x28",
                    "0x000000401004  e8 17 02 00 00       call 0x401220",
                    "0x000000401009  e9 a2 00 00 00       jmp 0x4010b0",
                ],
            },
            "confidence": "confirmed",
            "provenance": "parsed",
            "evidence": "",
            "subject": "app.exe",
        },
        {
            "id": 2,
            "stage": "disasm",
            "tool": "capstone",
            "kind": "disassembly",
            "key": "export:SubFunc",
            "value": {
                "arch": "x86-64",
                "address": "0x401220",
                "lines": [
                    "0x000000401220  c3                   ret",
                ],
            },
            "confidence": "confirmed",
            "provenance": "parsed",
            "evidence": "",
            "subject": "app.exe",
        },
        {
            "id": 3,
            "stage": "binary",
            "tool": "lief",
            "kind": "imports",
            "key": "imported_functions",
            "value": {"count": 1, "items": ["ExitProcess"]},
            "confidence": "confirmed",
            "provenance": "parsed",
            "evidence": "",
            "subject": "app.exe",
        },
    ]

    page._populate_callgraph(mock_rows)
    assert page.tree_calls.topLevelItemCount() == 2

    # Verify first entry has callee children
    entry_item = page.tree_calls.topLevelItem(0)
    assert entry_item.childCount() == 2
    callee1 = entry_item.child(0)
    assert "0x401220" in callee1.text(0)
    assert "SubFunc" in callee1.text(1)


def test_reconstruct_specification_and_multi_module(tmp_path):
    mock_findings = [
        {
            "stage": "binary",
            "tool": "lief",
            "kind": "binary",
            "key": "header",
            "value": {"format": "ELF", "arch": "X86_64", "bits": 64, "endianness": "Little", "nx": True, "pie": True},
        },
        {
            "stage": "binary",
            "tool": "lief",
            "kind": "dependencies",
            "key": "libraries",
            "value": ["libc.so.6", "libm.so.6"],
        },
        {
            "stage": "strings",
            "tool": "reforge.strings",
            "kind": "network",
            "key": "urls",
            "value": ["https://api.example.com/v1/status"],
        },
        {
            "stage": "strings",
            "tool": "reforge.strings",
            "kind": "indicators",
            "key": "windows_paths",
            "value": ["C:\\Config\\settings.ini"],
        },
    ]

    spec = generate_specification(mock_findings, "TestReconApp")
    assert "# Clean-Room Functional Specification: TestReconApp" in spec
    assert "ELF" in spec
    assert "libc.so.6" in spec
    assert "https://api.example.com/v1/status" in spec
    assert "Clean-Room Mandate" in spec

    # Test multi-module scaffolding
    dest = tmp_path / "multi_mod_recon"
    files = scaffold_project(
        dest,
        "TestReconApp",
        "python",
        [{"name": "Auth Service", "category": "Security"}],
        spec,
    )

    assert "SPECIFICATION.md" in files
    assert "src/testreconapp/core.py" in files
    assert "src/testreconapp/models.py" in files
    assert "src/testreconapp/client.py" in files
    assert "src/testreconapp/cli.py" in files
    assert "tests/test_core.py" in files
    assert "tests/test_models.py" in files

    # Execute tests live
    res = run_project_tests(dest, timeout=30)
    assert res.ok
    assert "passed" in res.stdout
