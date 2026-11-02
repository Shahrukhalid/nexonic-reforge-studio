import pytest

pytest.importorskip("PySide6")


def test_gui_launch_and_analyze(qtbot, samples):
    from reforge.ui.main_window import MainWindow

    w = MainWindow()
    qtbot.addWidget(w)
    w.show()
    assert w.nav.count() == 12
    for i in range(w.nav.count()):
        w.nav.setCurrentRow(i)          # every page refreshes without error

    imp = w.pages["Import Application"]
    imp.set_target(str(samples["asar"]))
    with qtbot.waitSignal(w.ctx.bridge.done, timeout=30000) as blocker:
        imp._start()
    assert blocker.args[1] == "done"
    ws = w.pages["Analysis Workspace"]
    qtbot.waitUntil(lambda: ws.tree.topLevelItemCount() > 0, timeout=5000)
    tools = w.pages["Tool Manager"]
    tools.refresh()
    assert tools.table.rowCount() == 85
    w.ctx.set_theme("light")
    w.close()


def test_tool_setup_panel_and_duplicate_detection(qtbot, samples):
    from reforge.ui.main_window import MainWindow

    w = MainWindow()
    qtbot.addWidget(w)
    tools = w.pages["Tool Manager"]
    tools.refresh()
    assert "Ghidra:" in tools.setup_status.text() and "JDK" in tools.setup_status.text()
    imp = w.pages["Import Application"]
    pid = w.ctx.db.create_project("asar", str(samples["asar"]), "standard")
    from reforge.analysis.orchestrator import Orchestrator
    Orchestrator(w.ctx.db).analyze(pid)
    assert imp._existing(samples["asar"])["id"] == pid          # same SHA-256 -> offered for re-run
    assert imp._existing(samples["jar"]) is None
    w.close()


def test_dashboard_columns_fit_window(qtbot, samples):
    from reforge.analysis.orchestrator import Orchestrator
    from reforge.ui.main_window import MainWindow
    w = MainWindow()
    qtbot.addWidget(w)
    w.resize(1000, 700)
    w.show()
    pid = w.ctx.db.create_project("Chess", str(samples["native"]), "deep")
    Orchestrator(w.ctx.db).analyze(pid)
    d = w.pages["Dashboard"]
    w.show_page("Dashboard")
    qtbot.wait(50)
    hh = d.table.horizontalHeader()
    right = hh.sectionViewportPosition(4) + hh.sectionSize(4)
    assert hh.sectionViewportPosition(4) < d.table.viewport().width()      # "Updated" column is visible
    assert right <= d.table.viewport().width() + 2
    w.close()
