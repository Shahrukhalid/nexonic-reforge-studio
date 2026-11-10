"""Implemented pages: Dashboard, Import, Analysis Workspace, Tool Manager, Logs, Settings."""
from __future__ import annotations

import datetime as dt
import json
import logging
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QFontDatabase
from PySide6.QtWidgets import (
    QAbstractItemView,
    QComboBox,
    QDialog,
    QFileDialog,
    QFormLayout,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QSpinBox,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
)

from ...analysis import report
from ...analysis.orchestrator import PROFILES
from ...core import paths
from ...tools import registry
from ..theme import status_color
from .common import Page, card


def _base(subject: str) -> str:
    return subject.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1] if subject else ""


def _ts(t: float) -> str:
    return dt.datetime.fromtimestamp(t).strftime("%Y-%m-%d %H:%M")


class NumItem(QTableWidgetItem):
    """Sorts numerically instead of as text."""

    def __lt__(self, other):
        try:
            return float(self.text()) < float(other.text())
        except ValueError:
            return super().__lt__(other)


def _ro(text, cls=QTableWidgetItem) -> QTableWidgetItem:
    it = cls(str(text))
    it.setFlags(it.flags() & ~Qt.ItemIsEditable)
    return it


# ------------------------------------------------------------------ Dashboard
class DashboardPage(Page):
    title = "Dashboard"
    subtitle = "Recent projects, active operations and tool health on this machine."

    def __init__(self, ctx):
        super().__init__(ctx)
        grid = QGridLayout()
        grid.setSpacing(12)
        self.c_proj = card("Projects")
        self.c_done = card("Completed analyses")
        self.c_active = card("Active operations")
        self.c_tools = card("Operational tools")
        for i, (f, _) in enumerate((self.c_proj, self.c_done, self.c_active, self.c_tools)):
            grid.addWidget(f, 0, i)
        self.root.addLayout(grid)
        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["Name", "Format / SHA-256", "Profile", "Status", "Updated"])
        hh = self.table.horizontalHeader()
        for c in range(5):
            hh.setSectionResizeMode(c, QHeaderView.ResizeToContents)
        hh.setStretchLastSection(True)          # spare width goes to "Updated", never pushes columns off-screen
        self.table.setTextElideMode(Qt.ElideMiddle)
        self.table.verticalHeader().hide()
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.cellDoubleClicked.connect(self._open)
        self.root.addWidget(QLabel("Recent projects"))
        self.root.addWidget(self.table, 1)

    def refresh(self):
        projs = self.ctx.db.projects()
        self.c_proj[1].setText(str(len(projs)))
        self.c_done[1].setText(str(sum(p["status"] == "complete" for p in projs)))
        self.c_active[1].setText(str(len(self.ctx.tasks.active())))
        sts = registry.all_status()
        self.c_tools[1].setText(f"{sum(s.available for s in sts)} / {len(sts)}")
        self.table.setRowCount(len(projs))
        self._ids = [p["id"] for p in projs]
        for r, p in enumerate(projs):
            fmt = self.ctx.db.findings(p["id"], stage="identify", kind="format")
            desc = fmt[0]["value"].get("description", "") if fmt else "—"
            sha = (p["sha256"] or "")[:16]
            vals = [p["name"], f"{desc}  ·  {sha}…" if sha else f"{desc}  ·  (bundle: per-file hashes in workspace)",
                    p["profile"], p["status"], _ts(p["updated"])]
            for c, v in enumerate(vals):
                it = _ro(v)
                if c == 1 and p["sha256"]:
                    it.setToolTip(p["sha256"])
                self.table.setItem(r, c, it)
        self.table.resizeColumnToContents(4)

    def _open(self, row, _col):
        self.ctx.open_project(self._ids[row])


# ------------------------------------------------------------------ Import
class DropFrame(QFrame):
    def __init__(self, on_drop):
        super().__init__()
        self.setObjectName("Drop")
        self.setAcceptDrops(True)
        self.on_drop = on_drop
        lay = QVBoxLayout(self)
        lbl = QLabel("Drop an application, package or binary here\n"
                     ".app .dmg .pkg .exe .dll .msi .apk .aab .ipa .jar .asar .wasm ELF Mach-O ...")
        lbl.setAlignment(Qt.AlignCenter)
        lbl.setObjectName("Muted")
        lay.addWidget(lbl)
        self.setMinimumHeight(170)

    def dragEnterEvent(self, e):
        if e.mimeData().hasUrls():
            self.setProperty("hover", True)
            self.style().polish(self)
            e.acceptProposedAction()

    def dragLeaveEvent(self, _e):
        self.setProperty("hover", False)
        self.style().polish(self)

    def dropEvent(self, e):
        self.dragLeaveEvent(e)
        urls = [u.toLocalFile() for u in e.mimeData().urls() if u.isLocalFile()]
        if urls:
            self.on_drop(urls[0])


class ImportPage(Page):
    title = "Import Application"
    subtitle = ("Imported files are treated as untrusted and are never executed. Analysis is static; "
                "originals are opened read-only.")

    def __init__(self, ctx):
        super().__init__(ctx)
        self.drop = DropFrame(self.set_target)
        self.root.addWidget(self.drop)
        row = QHBoxLayout()
        self.path = QLineEdit()
        self.path.setPlaceholderText("Path to file or .app bundle")
        b1 = QPushButton("Browse file…")
        b1.clicked.connect(self._browse)
        b2 = QPushButton("Browse folder/bundle…")
        b2.clicked.connect(self._browse_dir)
        row.addWidget(self.path, 1)
        row.addWidget(b1)
        row.addWidget(b2)
        self.root.addLayout(row)
        row2 = QHBoxLayout()
        self.profile = QComboBox()
        self.profile.addItems([p.capitalize() + " scan" for p in PROFILES])
        self.profile.setCurrentIndex(1)
        self.go = QPushButton("Analyze")
        self.go.setObjectName("Primary")
        self.go.clicked.connect(self._start)
        self.cancel = QPushButton("Cancel")
        self.cancel.setEnabled(False)
        self.cancel.clicked.connect(self._cancel)
        row2.addWidget(QLabel("Profile"))
        row2.addWidget(self.profile)
        row2.addStretch(1)
        row2.addWidget(self.cancel)
        row2.addWidget(self.go)
        self.root.addLayout(row2)
        self.bar = QProgressBar()
        self.bar.setValue(0)
        self.msg = QLabel("")
        self.msg.setObjectName("Muted")
        self.root.addWidget(self.bar)
        self.root.addWidget(self.msg)
        self.root.addStretch(1)
        self._task = None
        self._pid = None
        ctx.bridge.progress.connect(self._on_progress)
        ctx.bridge.done.connect(self._on_done)

    def set_target(self, p: str):
        self.path.setText(p)

    def _browse(self):
        f, _ = QFileDialog.getOpenFileName(self, "Select target")
        if f:
            self.set_target(f)

    def _browse_dir(self):
        d = QFileDialog.getExistingDirectory(self, "Select bundle or folder")
        if d:
            self.set_target(d)

    def _start(self):
        p = Path(self.path.text().strip())
        if not p.exists():
            QMessageBox.warning(self, "Import", "Path does not exist.")
            return
        prof = PROFILES[self.profile.currentIndex()]
        existing = self._existing(p)
        if existing:
            ans = QMessageBox.question(
                self, "Already analysed",
                f"Project #{existing['id']} ({existing['name']}) analysed this same input before.\n\n"
                "Yes: re-run that project with the selected profile.\nNo: create a new project.",
                QMessageBox.Yes | QMessageBox.No | QMessageBox.Cancel)
            if ans == QMessageBox.Cancel:
                return
            if ans == QMessageBox.Yes:
                self.ctx.db.update_project(existing["id"], profile=prof)
                self._pid = existing["id"]
                self._task = self.ctx.start_analysis(self._pid)
                self.go.setEnabled(False)
                self.cancel.setEnabled(True)
                self.bar.setValue(0)
                return
        self._pid = self.ctx.db.create_project(p.name, str(p.resolve()), prof)
        self._task = self.ctx.start_analysis(self._pid)
        self.go.setEnabled(False)
        self.cancel.setEnabled(True)
        self.bar.setValue(0)

    def _existing(self, p: Path) -> dict | None:
        """Same file (SHA-256) or same bundle path analysed before."""
        rp = str(p.resolve())
        projs = self.ctx.db.projects()
        if p.is_file():
            from ...analysis.identify import file_hashes
            sha = file_hashes(p)["sha256"]
            return next((x for x in projs if x["sha256"] == sha), None)
        return next((x for x in projs if x["input_path"] == rp), None)

    def _cancel(self):
        if self._task:
            self.ctx.tasks.cancel(self._task)

    def _on_progress(self, task_id, pct, msg):
        if task_id == self._task:
            self.bar.setValue(pct)
            self.msg.setText(msg)

    def _on_done(self, task_id, status, result):
        if task_id != self._task:
            return
        self.go.setEnabled(True)
        self.cancel.setEnabled(False)
        if status == "done":
            self.msg.setText(f"Complete: {json.dumps(result)[:300]}")
            self.ctx.open_project(self._pid)
        else:
            self.msg.setText(f"{status}: {result}")
        self._task = None


# ------------------------------------------------------------------ Analysis workspace
class AnalysisPage(Page):
    title = "Analysis Workspace"
    subtitle = "Findings grouped by stage. Each finding shows its tool, confidence and provenance."

    def __init__(self, ctx):
        super().__init__(ctx)
        top = QHBoxLayout()
        self.sel = QComboBox()
        self.sel.currentIndexChanged.connect(self._load)
        self.rerun = QPushButton("Re-run")
        self.rerun.clicked.connect(self._rerun)
        exp = QPushButton("Export report…")
        exp.clicked.connect(self._export)
        dele = QPushButton("Delete project")
        dele.clicked.connect(self._delete)
        self.imhex = QPushButton("Open in ImHex")
        self.imhex.setToolTip("Opens a copy of the input file in ImHex (external hex editor)")
        self.imhex.clicked.connect(self._open_imhex)
        self.filter = QLineEdit()
        self.filter.setPlaceholderText("Filter findings…")
        self.filter.textChanged.connect(self._apply_filter)
        top.addWidget(QLabel("Project"))
        top.addWidget(self.sel, 1)
        top.addWidget(self.filter, 1)
        top.addWidget(self.rerun)
        top.addWidget(exp)
        top.addWidget(self.imhex)
        top.addWidget(dele)
        self.root.addLayout(top)
        split = QSplitter()
        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Finding", "Subject", "Confidence", "Tool"])
        self.tree.header().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.tree.header().setStretchLastSection(True)
        self.tree.currentItemChanged.connect(self._show)
        self.detail = QPlainTextEdit()
        self.detail.setReadOnly(True)
        self.detail.setLineWrapMode(QPlainTextEdit.NoWrap)
        self.detail.setFont(QFontDatabase.systemFont(QFontDatabase.FixedFont))
        split.addWidget(self.tree)
        split.addWidget(self.detail)
        split.setSizes([520, 520])
        self.root.addWidget(split, 1)
        self._rows: list[dict] = []
        self._ids: list[int] = []

    def refresh(self, select: int | None = None):
        cur = select if select is not None else (self._ids[self.sel.currentIndex()] if self._ids and self.sel.currentIndex() >= 0 else None)
        projs = self.ctx.db.projects()
        self._ids = [p["id"] for p in projs]
        self.sel.blockSignals(True)
        self.sel.clear()
        self.sel.addItems([f"#{p['id']} {p['name']} — {p['status']}" for p in projs])
        if cur in self._ids:
            self.sel.setCurrentIndex(self._ids.index(cur))
        self.sel.blockSignals(False)
        self._load()

    def _pid(self):
        i = self.sel.currentIndex()
        return self._ids[i] if 0 <= i < len(self._ids) else None

    def _load(self, *_):
        self.tree.clear()
        self.detail.clear()
        pid = self._pid()
        if pid is None:
            return
        self._rows = self.ctx.db.findings(pid)
        by_stage: dict[str, list[dict]] = {}
        for r in self._rows:
            by_stage.setdefault(r["stage"], []).append(r)
        for stage, rows in by_stage.items():
            g = QTreeWidgetItem([f"{stage}  ({len(rows)})"])
            self.tree.addTopLevelItem(g)
            subjects = list(dict.fromkeys(r["subject"] for r in rows))
            nested = len(subjects) > 1
            parents: dict[str, QTreeWidgetItem] = {}
            for r in rows:
                parent = g
                if nested:
                    parent = parents.get(r["subject"])
                    if parent is None:
                        parent = QTreeWidgetItem([_base(r["subject"]) or "(project)"])
                        parent.setToolTip(0, r["subject"])
                        parents[r["subject"]] = parent
                        g.addChild(parent)
                it = QTreeWidgetItem([f"{r['kind']} · {r['key']}", _base(r["subject"]), r["confidence"], r["tool"]])
                it.setToolTip(0, f"{r['kind']} · {r['key']}")
                it.setToolTip(1, r["subject"])
                it.setData(0, Qt.UserRole, r["id"])
                parent.addChild(it)
            g.setExpanded(True)
            for p in parents.values():
                p.setExpanded(len(parents) <= 3)
        self._apply_filter(self.filter.text())
        first = self.tree.topLevelItem(0)
        while first is not None and first.childCount():
            first = first.child(0)
        if first is not None:
            self.tree.setCurrentItem(first)

    def _apply_filter(self, text: str):
        t = text.lower()

        def walk(node) -> bool:
            if node.childCount() == 0:
                hit = not t or any(t in node.text(k).lower() for k in range(4)) or t in (node.toolTip(1) or "").lower()
                node.setHidden(not hit)
                return hit
            any_hit = False
            for j in range(node.childCount()):
                any_hit |= walk(node.child(j))
            node.setHidden(bool(t) and not any_hit)
            return any_hit

        for i in range(self.tree.topLevelItemCount()):
            walk(self.tree.topLevelItem(i))

    def _show(self, it, _prev):
        if not it or it.data(0, Qt.UserRole) is None:
            return
        fid = it.data(0, Qt.UserRole)
        r = next((x for x in self._rows if x["id"] == fid), None)
        if not r:
            return
        head = (f"{r['kind']} · {r['key']}\nfile: {r['subject']}\ntool: {r['tool']}   confidence: {r['confidence']}"
                f"   provenance: {r['provenance']}\nevidence: {r['evidence']}\n" + "─" * 72 + "\n")
        v = r["value"]
        if isinstance(v, dict) and "lines" in v:
            body = f"; {v.get('arch')} @ {v.get('address')}\n" + "\n".join(v["lines"])
        elif isinstance(v, dict) and "code" in v:
            if r["provenance"] == "decompiled":
                head_c = "// DECOMPILED REPRESENTATION - not original source code\n"
                if v.get("signature") or v.get("entry"):
                    head_c += f"// {v.get('signature', '')}  @ {v.get('entry', '')}\n"
            else:
                head_c = f"<!-- decoded from the file's own structure ({r['provenance']}) -->\n"
            body = head_c + "\n" + v["code"]
        else:
            body = json.dumps(v, indent=2, default=str)
        self.detail.setPlainText(head + body)

    def _rerun(self):
        pid = self._pid()
        if pid:
            self.ctx.start_analysis(pid)

    def _export(self):
        pid = self._pid()
        if not pid:
            return
        f, _ = QFileDialog.getSaveFileName(self, "Export report", f"reforge_report_{pid}.md",
                                           "Markdown (*.md);;JSON (*.json)")
        if f:
            report.export(self.ctx.db, pid, Path(f))
            self.ctx.status(f"Report exported: {f}")

    def _open_imhex(self):
        from ...tools.external import ExternalToolError, open_in_imhex
        pid = self._pid()
        p = self.ctx.db.project(pid) if pid else None
        if not p:
            return
        try:
            _, copy = open_in_imhex(Path(p["input_path"]), Path(p["workdir"]) if p.get("workdir") else None)
            self.ctx.status(f"Opened a copy in ImHex: {copy}")
        except (ExternalToolError, OSError) as e:
            QMessageBox.information(self, "ImHex", str(e))

    def _delete(self):
        pid = self._pid()
        if pid and QMessageBox.question(self, "Delete", "Delete project and its extracted files? "
                                        "The original input is not touched.") == QMessageBox.Yes:
            self.ctx.db.delete_project(pid)
            self.refresh()


# ------------------------------------------------------------------ Tool manager
class ToolsPage(Page):
    title = "Tool Manager"
    subtitle = ("All 85 catalogued integrations with live status on this machine. "
                "Licence/maintenance data shows 'pending' until verified against GitHub.")

    def __init__(self, ctx):
        super().__init__(ctx)
        top = QHBoxLayout()
        self.filter = QLineEdit()
        self.filter.setPlaceholderText("Filter by name, category, status…")
        self.filter.textChanged.connect(self._filter)
        b = QPushButton("Re-check")
        b.clicked.connect(self.refresh)
        self.summary = QLabel("")
        self.summary.setObjectName("Muted")
        top.addWidget(self.filter, 1)
        top.addWidget(b)
        self.root.addLayout(top)
        self.root.addWidget(self._setup_panel())
        self.root.addWidget(self.summary)
        cols = ["#", "Tool", "Category", "Status", "Version / location", "Platforms", "License", "Integration",
                "Verification", "Notes"]
        self.table = QTableWidget(0, len(cols))
        self.table.setHorizontalHeaderLabels(cols)
        self.table.verticalHeader().hide()
        self.table.setSortingEnabled(True)
        self.table.horizontalHeader().setSectionResizeMode(9, QHeaderView.Stretch)
        self.table.setAlternatingRowColors(True)
        self.root.addWidget(self.table, 1)

    # ---- verified tool packs setup ------------------------------------------
    def _setup_panel(self) -> QFrame:
        f = QFrame()
        f.setObjectName("Card")
        lay = QVBoxLayout(f)
        lay.setContentsMargins(16, 12, 16, 12)
        head = QHBoxLayout()
        t = QLabel("Verified Tool Packs")
        t.setStyleSheet("font-weight:600")
        head.addWidget(t)

        from ...tools import toolpacks
        self.pack_sel = QComboBox()
        for pid, spec in toolpacks.packs().items():
            self.pack_sel.addItem(f"{spec['name']} {spec['version']}", pid)
        self.pack_sel.currentIndexChanged.connect(self._refresh_setup)
        head.addWidget(self.pack_sel)
        head.addStretch(1)

        self.b_install = QPushButton("Install")
        self.b_install.setObjectName("Primary")
        self.b_install.clicked.connect(self._install_pack)
        self.b_uninstall = QPushButton("Uninstall")
        self.b_uninstall.clicked.connect(self._uninstall_pack)
        self.b_build = QPushButton("Build decompiler")
        self.b_build.clicked.connect(self._build_natives)
        self.b_notices = QPushButton("Licenses & Notices…")
        self.b_notices.clicked.connect(self._show_notices)

        head.addWidget(self.b_install)
        head.addWidget(self.b_uninstall)
        head.addWidget(self.b_build)
        head.addWidget(self.b_notices)
        lay.addLayout(head)

        self.setup_status = QLabel("")
        self.setup_status.setObjectName("Muted")
        self.setup_status.setWordWrap(True)
        self.setup_status.setTextInteractionFlags(Qt.TextSelectableByMouse)
        lay.addWidget(self.setup_status)
        self.setup_bar = QProgressBar()
        self.setup_bar.hide()
        lay.addWidget(self.setup_bar)
        self._setup_task = None
        self.ctx.bridge.progress.connect(self._setup_progress)
        self.ctx.bridge.done.connect(self._setup_done)
        return f

    def _selected_pid(self) -> str:
        return self.pack_sel.currentData() or "ghidra"

    def _refresh_setup(self):
        from ...tools import toolpacks
        from ...tools.setup import ghidra_status
        pid = self._selected_pid()
        spec = toolpacks.packs().get(pid, {})
        installed = toolpacks.is_installed(pid)
        busy = self._setup_task is not None

        if pid == "ghidra":
            s = ghidra_status()
            parts = [("Ghidra: installed" if s["installed"] else "Ghidra: not installed"),
                     (f"JDK {s['java_required']}+: {s['java']}" if s["java"] else
                      f"JDK {s['java_required']}+: MISSING (macOS: brew install openjdk@{s['java_required']})")]
            if s["installed"]:
                parts.append(f"decompiler ({s['platform']}): " + ("OK" if s["decompiler"] else "missing - click Build decompiler"))
            self.b_build.show()
            self.b_build.setEnabled(not busy and s["installed"] and not s["decompiler"] and bool(s["java"]))
        else:
            self.b_build.hide()
            status_text = "installed" if installed else "not installed"
            req = f" · Requires: {spec.get('requires')}" if spec.get("requires") else ""
            size = f" (≈{spec.get('size_hint_mb', 50)} MB, SHA-256 verified)"
            parts = [f"{spec.get('name', pid)}: {status_text}{size if not installed else ''}{req}"]

        self.setup_status.setText("   ·   ".join(parts))
        self.b_install.setText("Re-install / Repair" if installed else "Install (SHA-256 verified)")
        self.b_install.setEnabled(not busy)
        self.b_uninstall.setEnabled(not busy and installed)

    def _install_pack(self):
        from ...tools import toolpacks
        pid = self._selected_pid()
        spec = toolpacks.packs()[pid]
        self.setup_bar.setRange(0, 100)
        self.setup_bar.show()

        def job(tctx):
            def prog(done, total):
                tctx.progress(int(done * 100 / total) if total else 0,
                              f"Downloading {spec.get('name', pid)} ({done >> 20} MB)")
            return str(toolpacks.install(pid, prog))

        self._setup_task = self.ctx.tasks.submit(
            job, on_progress=lambda p, m: self.ctx.bridge.progress.emit(self._setup_task or "", p, m),
            on_done=lambda t, s, r: self.ctx.bridge.done.emit(t, s, r))
        self._refresh_setup()

    def _uninstall_pack(self):
        from ...tools import toolpacks
        pid = self._selected_pid()
        if QMessageBox.question(self, "Uninstall", f"Uninstall {pid} tool pack?") == QMessageBox.Yes:
            toolpacks.uninstall(pid)
            self.ctx.status(f"Uninstalled {pid}")
            self.refresh()

    def _show_notices(self):
        root = Path(__file__).resolve().parents[3]
        notices_file = root / "THIRD_PARTY_NOTICES.md"
        text = notices_file.read_text(errors="replace") if notices_file.is_file() else "No notices file found."
        dlg = QDialog(self)
        dlg.setWindowTitle("Third-Party Notices & Licensing")
        dlg.resize(700, 500)
        v = QVBoxLayout(dlg)
        ed = QPlainTextEdit()
        ed.setReadOnly(True)
        ed.setPlainText(text)
        v.addWidget(ed)
        btn = QPushButton("Close")
        btn.clicked.connect(dlg.accept)
        v.addWidget(btn)
        dlg.exec()

    def _build_natives(self):
        from ...tools.setup import build_ghidra_natives
        self.setup_bar.setRange(0, 0)       # indeterminate
        self.setup_bar.show()
        log = logging.getLogger("reforge.setup")
        self._setup_task = self.ctx.tasks.submit(
            lambda tctx: build_ghidra_natives(log.info),
            on_done=lambda t, s, r: self.ctx.bridge.done.emit(t, s, r))
        self.setup_status.setText("Building Ghidra decompiler… (progress in Activity & Logs)")
        self.b_build.setEnabled(False)

    def _setup_progress(self, tid, pct, msg):
        if tid and tid == self._setup_task:
            self.setup_bar.setValue(pct)
            self.setup_status.setText(msg)

    def _setup_done(self, tid, status, result):
        if tid != self._setup_task:
            return
        self._setup_task = None
        self.setup_bar.hide()
        ok = status == "done" and result not in (False, None)
        self.ctx.status("Tool setup " + ("finished" if ok else f"failed: {result}"))
        from ...tools import jdk
        jdk.find_jdk.cache_clear()
        self.refresh()

    def refresh(self):
        self._refresh_setup()
        sts = registry.all_status()
        self.table.setSortingEnabled(False)
        self.table.setRowCount(len(sts))
        for r, s in enumerate(sts):
            e = s.entry
            vals = [e["id"], e["name"], e["category"], s.status, s.version or s.location or "",
                    ", ".join(e["platforms"]), e["license"], e["integration"], e["verification"], e["notes"]]
            for c, v in enumerate(vals):
                it = _ro(v, NumItem if c == 0 else QTableWidgetItem)
                if c == 3:
                    it.setForeground(QColor(status_color(s.status, self.ctx.theme)))
                it.setToolTip(e["repo"])
                self.table.setItem(r, c, it)
        self.table.setSortingEnabled(True)
        if not getattr(self, "_sorted_once", False):
            self.table.sortItems(0, Qt.AscendingOrder)
            self._sorted_once = True
        self.table.resizeColumnsToContents()
        self.summary.setText("  ·  ".join(f"{k}: {v}" for k, v in sorted(registry.summary().items())))
        self._filter(self.filter.text())

    def _filter(self, t: str):
        t = t.lower()
        for r in range(self.table.rowCount()):
            txt = " ".join(self.table.item(r, c).text().lower() for c in range(self.table.columnCount()))
            self.table.setRowHidden(r, bool(t) and t not in txt)


# ------------------------------------------------------------------ Logs
class LogsPage(Page):
    title = "Activity & Logs"
    subtitle = "Live application log (secrets are never written to logs)."

    def __init__(self, ctx):
        super().__init__(ctx)
        self.view = QPlainTextEdit()
        self.view.setReadOnly(True)
        self.view.setMaximumBlockCount(20000)
        self.root.addWidget(self.view, 1)
        ctx.bridge.log.connect(self.view.appendPlainText)
        lbl = QLabel(f"Log file: {paths.log_path()}")
        lbl.setObjectName("Muted")
        lbl.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.root.addWidget(lbl)


# ------------------------------------------------------------------ Settings
class SettingsPage(Page):
    title = "Settings"
    subtitle = "Appearance and analysis safety limits. AI provider keys arrive with Milestone 7 (OS keychain storage)."

    def __init__(self, ctx):
        super().__init__(ctx)
        f = QFrame()
        f.setObjectName("Card")
        form = QFormLayout(f)
        form.setContentsMargins(18, 16, 18, 16)
        self.theme = QComboBox()
        self.theme.addItems(["dark", "light"])
        self.theme.setCurrentText(ctx.theme)
        self.theme.currentTextChanged.connect(ctx.set_theme)
        self.max_files = QSpinBox()
        self.max_files.setRange(100, 1_000_000)
        self.max_files.setValue(ctx.limits.max_files)
        self.max_gb = QSpinBox()
        self.max_gb.setRange(1, 200)
        self.max_gb.setSuffix(" GiB")
        self.max_gb.setValue(max(1, ctx.limits.max_total_bytes // 1024**3))
        self.timeout = QSpinBox()
        self.timeout.setRange(10, 7200)
        self.timeout.setSuffix(" s")
        self.timeout.setValue(ctx.limits.tool_timeout_s)
        save = QPushButton("Save limits")
        save.setObjectName("Primary")
        save.clicked.connect(self._save)
        dd = QLabel(str(paths.data_dir()))
        dd.setTextInteractionFlags(Qt.TextSelectableByMouse)
        form.addRow("Theme", self.theme)
        form.addRow("Max extracted files", self.max_files)
        form.addRow("Max extracted size", self.max_gb)
        form.addRow("Tool timeout", self.timeout)
        form.addRow("Data directory", dd)
        form.addRow("", save)
        self.root.addWidget(f)
        note = QLabel("Dynamic (runtime) analysis is disabled: no verified isolation environment is configured. "
                      "ReForge never executes imported applications on the host.")
        note.setWordWrap(True)
        note.setObjectName("Muted")
        self.root.addWidget(note)
        self.root.addStretch(1)

    def _save(self):
        lim = self.ctx.limits
        lim.max_files = self.max_files.value()
        lim.max_total_bytes = self.max_gb.value() * 1024**3
        lim.tool_timeout_s = self.timeout.value()
        self.ctx.db.set_setting("limits", {"max_files": lim.max_files, "max_total_bytes": lim.max_total_bytes,
                                           "tool_timeout_s": lim.tool_timeout_s})
        self.ctx.status("Settings saved")
