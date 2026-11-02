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
