"""Milestone 8 tests: Reconstruction Studio, Scaffolding, Runner, and Workspace."""
from pathlib import Path

from reforge.analysis.orchestrator import Orchestrator
from reforge.reconstruct import detect_runner_commands, run_project_tests, scaffold_project
from reforge.ui.main_window import MainWindow


def test_scaffold_python(tmp_path):
    dest = tmp_path / "py_reforge"
    files = scaffold_project(dest, "Demo App", "python", [{"name": "Auth API", "category": "Network"}], "# Spec")
    assert "pyproject.toml" in files
    assert "SPECIFICATION.md" in files
    assert "CLEAN_ROOM_NOTICE.md" in files
    assert (dest / "src" / "demo_app" / "client.py").is_file()
    assert (dest / "tests" / "test_main.py").is_file()


def test_scaffold_typescript(tmp_path):
    dest = tmp_path / "ts_reforge"
    files = scaffold_project(dest, "Demo TS", "typescript", [], "# Spec")
    assert "package.json" in files
    assert "tsconfig.json" in files
    assert (dest / "src" / "index.ts").is_file()


def test_scaffold_rust(tmp_path):
    dest = tmp_path / "rs_reforge"
    files = scaffold_project(dest, "Demo Rust", "rust", [], "# Spec")
    assert "Cargo.toml" in files
    assert (dest / "src" / "main.rs").is_file()


def test_runner_detection(tmp_path):
    dest = tmp_path / "run_test"
    scaffold_project(dest, "Test Runner", "python", [], "# Spec")
    cmds = detect_runner_commands(dest)
    assert "test" in cmds
    assert "pytest" in " ".join(cmds["test"])


def test_run_project_tests_live(tmp_path):
    dest = tmp_path / "live_test"
    scaffold_project(dest, "Live Test", "python", [], "# Spec")
    # Run tests on the generated project
    res = run_project_tests(dest, timeout=30)
    assert res.ok
    assert "passed" in res.stdout


def test_reconstruction_studio_page(db, samples, qapp, monkeypatch):
    from PySide6.QtWidgets import QMessageBox
    monkeypatch.setattr(QMessageBox, "information", lambda *args, **kwargs: QMessageBox.Ok)
    monkeypatch.setattr(QMessageBox, "warning", lambda *args, **kwargs: QMessageBox.Ok)

    win = MainWindow()
    win.ctx.db = db
    pid = db.create_project("test_recon", str(samples["apk"]), "standard")
    Orchestrator(db).analyze(pid)

    page = win.pages["Reconstruction Studio"]
    page.refresh(select=pid)

    assert page.current_pid == pid
    assert page.table_features.rowCount() > 0
    assert page.txt_spec.toPlainText() != ""

    # Test scaffold button
    page._scaffold_project()
    p = db.project(pid)
    recon_dir = Path(p["workdir"]) / "reconstructed"
    assert recon_dir.is_dir()
    assert any(recon_dir.iterdir())
    assert page.btn_open_ws.isEnabled()

    win.close()


def test_workspace_page(db, samples, qapp):
    win = MainWindow()
    win.ctx.db = db
    pid = db.create_project("test_ws", str(samples["apk"]), "standard")
    Orchestrator(db).analyze(pid)

    # Scaffold a project first
    p = db.project(pid)
    recon_dir = Path(p["workdir"]) / "reconstructed" / "my_app"
    scaffold_project(recon_dir, "My App", "python", [], "# Spec")

    ws_page = win.pages["Source Code Workspace"]
    ws_page.refresh(select=pid)

    assert ws_page.current_pid == pid
    assert ws_page.file_tree.topLevelItemCount() > 0

    # Open a file in editor tab
    main_py = recon_dir / "src" / "my_app" / "main.py"
    ws_page._open_file(main_py)
    assert ws_page.editor_tabs.count() == 1
    assert "Initialized" in ws_page.editor_tabs.currentWidget().toPlainText()

    # Save
    ws_page._save_current_file()

    # Close tab
    ws_page._close_tab(0)
    assert ws_page.editor_tabs.count() == 0

    win.close()
