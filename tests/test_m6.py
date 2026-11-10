"""Milestone 6 tests: Application Explorer and Visual UI Explorer."""
from PySide6.QtGui import QTextDocument

from reforge.analysis.orchestrator import Orchestrator
from reforge.ui.highlighter import CodeHighlighter
from reforge.ui.main_window import MainWindow


def test_code_highlighter():
    doc = QTextDocument()
    hl = CodeHighlighter(doc, lang="python", theme="dark")
    doc.setPlainText("def foo():\n    return 'hello' # comment\n")
    hl.set_language("xml")
    doc.setPlainText("<manifest package='com.test'><activity name='MainActivity'/></manifest>")
    hl.set_theme("light")
    assert doc.toPlainText().startswith("<manifest")


def test_application_explorer_page(db, samples, qapp):
    win = MainWindow()
    win.ctx.db = db
    pid = db.create_project("test_app", str(samples["apk"]), "standard")
    Orchestrator(db).analyze(pid)

    page = win.pages["Application Explorer"]
    page.refresh(select=pid)

    assert page.current_pid == pid
    assert page.tree_struct.topLevelItemCount() > 0
    assert page.table_deps.rowCount() > 0 or page.table_endpoints.rowCount() > 0 or page.table_strings.rowCount() > 0

    # Test selection
    top_item = page.tree_struct.topLevelItem(0)
    if top_item.childCount() > 0:
        page._on_struct_selected(top_item.child(0), None)
        assert page.code_edit.toPlainText() != ""

    # Test search filter
    page.search_input.setText("http")
    page.search_input.setText("")

    win.close()


def test_visual_ui_explorer_page(db, samples, tmp_path, qapp):
    win = MainWindow()
    win.ctx.db = db
    pid = db.create_project("test_ui", str(samples["apk"]), "standard")
    Orchestrator(db).analyze(pid)

    page = win.pages["Visual UI Explorer"]
    page.refresh(select=pid)

    assert page.current_pid == pid

    # Simulate importing a screenshot
    fake_screenshot = tmp_path / "mockup.png"
    # Write a minimal 1x1 PNG
    fake_screenshot.write_bytes(
        b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15c4\x00\x00\x00\nIDATx\x9cc\x00\x01\x00\x00\x05\x00\x01\r\n-\xb4\x00\x00\x00\x00IEND\xaeB`\x82"
    )

    import shutil
    shutil.copyfile(fake_screenshot, page.screenshots_dir / "mockup.png")
    page._load_project(pid)

    assert page.stats_lbl.text() != ""
    assert any("mockup.png" in page.asset_tree.topLevelItem(i).child(j).text(0)
               for i in range(page.asset_tree.topLevelItemCount())
               for j in range(page.asset_tree.topLevelItem(i).childCount()))

    win.close()
