from __future__ import annotations

import logging

from PySide6.QtCore import QObject, Signal
from PySide6.QtWidgets import (
    QApplication,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QMainWindow,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from .. import APP_NAME, PUBLISHER, __version__
from ..analysis.orchestrator import Orchestrator
from ..core.db import Database
from ..core.safety import Limits
from ..core.tasks import TaskManager
from .pages.common import PlannedPage
from .pages.main_pages import AnalysisPage, DashboardPage, ImportPage, LogsPage, SettingsPage, ToolsPage
from .theme import qss

log = logging.getLogger("reforge.ui")


class Bridge(QObject):
    """Thread-safe signals from worker threads to the GUI thread."""
    progress = Signal(str, int, str)
    done = Signal(str, str, object)
    log = Signal(str)


class QtLogHandler(logging.Handler):
    def __init__(self, bridge: Bridge):
        super().__init__()
        self.bridge = bridge
        self.setFormatter(logging.Formatter("%(asctime)s %(levelname)-7s %(name)s: %(message)s", "%H:%M:%S"))

    def emit(self, record):
        try:
            self.bridge.log.emit(self.format(record))
        except RuntimeError:
            pass


PLANNED = [
    ("Application Explorer", "Milestone 6", "Module, class, function, dependency and API-endpoint graph built from "
     "analysis findings, with feature relationships."),
    ("Visual UI Explorer", "Milestone 6", "Screen inventory from extracted resources (nibs/storyboards, XAML, "
     "Android layouts, HTML) plus imported reference screenshots."),
    ("AI Assistant", "Milestone 7", "Project-aware chat with BYOK providers (OpenRouter, Anthropic, OpenAI, Gemini) "
     "and local models (Ollama, llama.cpp). Keys stored in macOS Keychain / Windows Credential Manager. "
     "Paid usage requires explicit opt-in."),
    ("Reconstruction Studio", "Milestone 8", "Feature selection, specification approval and clean-room project "
     "generation with build/test loop. Generated code is always labelled as newly generated."),
    ("Source Code Workspace", "Milestone 8", "Explorer, editor, search and diff for generated projects."),
    ("Build & Export", "Milestone 9-10", "Source/project/report export and packaging of generated projects."),
]


class AppContext:
    def __init__(self, window: MainWindow):
        self.window = window
        self.db = Database()
        self.tasks = TaskManager(workers=2)
        self.bridge = Bridge()
        self.limits = Limits()
        saved = self.db.get_setting("limits") or {}
        for k, v in saved.items():
            if hasattr(self.limits, k):
                setattr(self.limits, k, v)
        self.theme = self.db.get_setting("theme", "dark")

    def start_analysis(self, pid: int) -> str:
        orch = Orchestrator(self.db, self.limits)
        holder = {}

        def job(ctx):
            holder["id"] = ctx.task_id
            return orch.analyze(pid, ctx)

        tid = self.tasks.submit(job, on_progress=lambda p, m: self.bridge.progress.emit(holder.get("id", ""), p, m),
                                on_done=lambda t, s, r: self.bridge.done.emit(t, s, r))
        holder["id"] = tid
        self.status(f"Analysis started for project #{pid}")
        return tid

    def open_project(self, pid: int):
        self.window.show_page("Analysis Workspace", select=pid)

    def status(self, msg: str):
        self.window.statusBar().showMessage(msg, 8000)
        log.info(msg)

    def set_theme(self, name: str):
        self.theme = name
        self.db.set_setting("theme", name)
        QApplication.instance().setStyleSheet(qss(name))


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(f"{APP_NAME} {__version__}")
        self._fit_to_screen()
        self.ctx = AppContext(self)
        handler = QtLogHandler(self.ctx.bridge)
        logging.getLogger("reforge").addHandler(handler)
        self.ctx.bridge.done.connect(self._on_task_done)

        central = QWidget()
        h = QHBoxLayout(central)
        h.setContentsMargins(0, 0, 0, 0)
        h.setSpacing(0)
        side = QWidget()
        side.setObjectName("Sidebar")
        side.setFixedWidth(230)
        sv = QVBoxLayout(side)
        sv.setContentsMargins(0, 0, 0, 8)
        brand = QLabel("ReForge Studio")
        brand.setObjectName("Brand")
        sub = QLabel(f"{PUBLISHER} · v{__version__}")
        sub.setObjectName("BrandSub")
        self.nav = QListWidget()
        self.nav.setObjectName("Nav")
        sv.addWidget(brand)
        sv.addWidget(sub)
        sv.addWidget(self.nav, 1)
        self.stack = QStackedWidget()
        h.addWidget(side)
        h.addWidget(self.stack, 1)
        self.setCentralWidget(central)

        self.pages = {}
        order = [DashboardPage, ImportPage, AnalysisPage]
        for cls in order:
            self._add(cls(self.ctx))
        for title, ms, scope in PLANNED:
            self._add(PlannedPage(self.ctx, title, ms, scope))
        for cls in (ToolsPage, LogsPage, SettingsPage):
            self._add(cls(self.ctx))
        self.nav.currentRowChanged.connect(self._switch)
        self.nav.setCurrentRow(0)
        self.statusBar().showMessage("Ready — static analysis only; imported files are never executed.")

    def _fit_to_screen(self):
        """Open at most 90% of the available screen, centred (never larger than the display)."""
        scr = QApplication.primaryScreen()
        if scr is None:
            self.resize(1320, 840)
            return
        g = scr.availableGeometry()
        w, h = min(1320, int(g.width() * 0.9)), min(840, int(g.height() * 0.9))
        self.resize(w, h)
        self.move(g.x() + (g.width() - w) // 2, g.y() + (g.height() - h) // 2)

    def _add(self, page):
        self.pages[page.title] = page
        self.stack.addWidget(page)
        self.nav.addItem(page.title)

    def _switch(self, row: int):
        self.stack.setCurrentIndex(row)
        self.stack.currentWidget().refresh()

    def show_page(self, title: str, **kw):
        idx = list(self.pages).index(title)
        self.nav.blockSignals(True)
        self.nav.setCurrentRow(idx)
        self.nav.blockSignals(False)
        self.stack.setCurrentIndex(idx)
        page = self.pages[title]
        page.refresh(**kw) if kw else page.refresh()

    def _on_task_done(self, _tid, status, result):
        self.ctx.status(f"Analysis {status}" + (f": {result}" if status != "done" else ""))
        cur = self.stack.currentWidget()
        if cur in (self.pages["Dashboard"], self.pages["Analysis Workspace"]):
            cur.refresh()

    def closeEvent(self, e):
        self.ctx.tasks.shutdown()
        super().closeEvent(e)
