"""Source Code Workspace: multi-tab code editor, file explorer, diff viewer, test runner."""
from __future__ import annotations

import difflib
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtGui import QFontDatabase, QKeySequence, QShortcut
from PySide6.QtWidgets import (
    QComboBox,
    QDialog,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSplitter,
    QTabWidget,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
)

from ...reconstruct.runner import run_project_build, run_project_tests
from ..highlighter import CodeHighlighter
from .common import Page


class SourceWorkspacePage(Page):
    title = "Source Code Workspace"
    subtitle = "Multi-tab editor, file explorer, diff viewer, and integrated test runner for clean-room projects."

    def __init__(self, ctx):
        super().__init__(ctx)
        self.current_pid: int | None = None
        self.reconstructed_dir: Path | None = None
        self.open_tabs: dict[str, QPlainTextEdit] = {}  # file_path -> editor

        # Top Bar
        top = QHBoxLayout()
        top.addWidget(QLabel("Project:"))
        self.proj_sel = QComboBox()
        self.proj_sel.currentIndexChanged.connect(self._on_project_changed)
        top.addWidget(self.proj_sel, 1)

        btn_save = QPushButton("Save (Ctrl+S)")
        btn_save.clicked.connect(self._save_current_file)
        top.addWidget(btn_save)

        btn_diff = QPushButton("Diff / Compare…")
        btn_diff.clicked.connect(self._show_diff)
        top.addWidget(btn_diff)

        btn_test = QPushButton("Run Tests")
        btn_test.setObjectName("Primary")
        btn_test.clicked.connect(self._run_tests)
        top.addWidget(btn_test)

        btn_build = QPushButton("Build / Check")
        btn_build.clicked.connect(self._run_build)
        top.addWidget(btn_build)

        self.root.addLayout(top)

        # Main Splitter
        split = QSplitter(Qt.Horizontal)

        # Left: File Tree Explorer
        left_w = QFrame()
        left_lay = QVBoxLayout(left_w)
        left_lay.setContentsMargins(0, 0, 0, 0)
        left_lay.setSpacing(6)

        tree_header = QHBoxLayout()
        lbl_files = QLabel("Reconstructed Project Files")
        lbl_files.setStyleSheet("font-weight: 600;")
        tree_header.addWidget(lbl_files)
        tree_header.addStretch(1)

        btn_new_file = QPushButton("+ File")
        btn_new_file.setFixedWidth(50)
        btn_new_file.clicked.connect(self._create_new_file)
        btn_refresh = QPushButton("↻")
        btn_refresh.setFixedWidth(32)
        btn_refresh.clicked.connect(self._refresh_file_tree)
        tree_header.addWidget(btn_new_file)
        tree_header.addWidget(btn_refresh)
        left_lay.addLayout(tree_header)

        self.file_tree = QTreeWidget()
        self.file_tree.setHeaderLabels(["File / Directory", "Size"])
        self.file_tree.header().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.file_tree.itemDoubleClicked.connect(self._on_file_double_clicked)
        left_lay.addWidget(self.file_tree, 1)

        split.addWidget(left_w)

        # Right: Editor & Console Splitter (Vertical)
        right_split = QSplitter(Qt.Vertical)

        # Multi-tab Editor
        self.editor_tabs = QTabWidget()
        self.editor_tabs.setTabsClosable(True)
        self.editor_tabs.tabCloseRequested.connect(self._close_tab)
        right_split.addWidget(self.editor_tabs)

        # Bottom Runner Console
        console_w = QFrame()
        console_lay = QVBoxLayout(console_w)
        console_lay.setContentsMargins(0, 0, 0, 0)
        console_lay.setSpacing(4)

        con_hdr = QHBoxLayout()
        self.con_title = QLabel("Execution Console & Test Output")
        self.con_title.setStyleSheet("font-weight: 600; font-size: 11px;")
        con_hdr.addWidget(self.con_title)
        con_hdr.addStretch(1)
        btn_clear_con = QPushButton("Clear")
        btn_clear_con.setFixedWidth(50)
        btn_clear_con.clicked.connect(lambda: self.console_output.clear())
        con_hdr.addWidget(btn_clear_con)
        console_lay.addLayout(con_hdr)

        self.console_output = QPlainTextEdit()
        self.console_output.setReadOnly(True)
        self.console_output.setFont(QFontDatabase.systemFont(QFontDatabase.FixedFont))
        self.console_output.setPlaceholderText("Test results, build output, and diagnostic logs will appear here.")
        console_lay.addWidget(self.console_output, 1)

        right_split.addWidget(console_w)
        right_split.setSizes([500, 180])

        split.addWidget(right_split)
        split.setSizes([320, 800])
        self.root.addWidget(split, 1)

        # Shortcut for Ctrl+S
        self.save_shortcut = QShortcut(QKeySequence("Ctrl+S"), self)
        self.save_shortcut.activated.connect(self._save_current_file)

    # ---- Lifecycle -----------------------------------------------------------
    def refresh(self, select: int | None = None) -> None:
        projs = self.ctx.db.projects()
        cur_data = self.proj_sel.currentData()
        self.proj_sel.blockSignals(True)
        self.proj_sel.clear()
        target_idx = 0
        for i, p in enumerate(projs):
            self.proj_sel.addItem(f"#{p['id']} · {p['name']} ({p['profile']})", p["id"])
            if select and p["id"] == select:
                target_idx = i
            elif not select and cur_data and p["id"] == cur_data:
                target_idx = i
        self.proj_sel.blockSignals(False)

        if projs:
            self.proj_sel.setCurrentIndex(target_idx)
            self._load_project(self.proj_sel.currentData())
        else:
            self.current_pid = None
            self.file_tree.clear()
            self.editor_tabs.clear()
            self.open_tabs.clear()

    def _on_project_changed(self, _idx: int):
        pid = self.proj_sel.currentData()
        if pid:
            self._load_project(pid)

    def _load_project(self, pid: int):
        self.current_pid = pid
        p = self.ctx.db.project(pid)
        if not p or not p.get("workdir"):
            return

        self.reconstructed_dir = Path(p["workdir"]) / "reconstructed"
        self.reconstructed_dir.mkdir(parents=True, exist_ok=True)
        self._refresh_file_tree()

    def _refresh_file_tree(self):
        self.file_tree.clear()
        if not self.reconstructed_dir or not self.reconstructed_dir.is_dir():
            return

        def add_items(parent_item, path: Path):
            for p in sorted(path.iterdir(), key=lambda x: (not x.is_dir(), x.name.lower())):
                if p.is_dir():
                    node = QTreeWidgetItem(parent_item, [p.name, ""])
                    node.setData(0, Qt.UserRole, str(p))
                    add_items(node, p)
                else:
                    sz = f"{p.stat().st_size:,} B"
                    node = QTreeWidgetItem(parent_item, [p.name, sz])
                    node.setData(0, Qt.UserRole, str(p))

        root_node = QTreeWidgetItem(self.file_tree, ["reconstructed", ""])
        root_node.setData(0, Qt.UserRole, str(self.reconstructed_dir))
        add_items(root_node, self.reconstructed_dir)
        self.file_tree.expandAll()

    # ---- Editor Actions ------------------------------------------------------
    def _on_file_double_clicked(self, item: QTreeWidgetItem, _col: int):
        path_str = item.data(0, Qt.UserRole)
        if not path_str:
            return
        p = Path(path_str)
        if p.is_file():
            self._open_file(p)

    def _open_file(self, p: Path):
        key = str(p.resolve())
        if key in self.open_tabs:
            self.editor_tabs.setCurrentWidget(self.open_tabs[key])
            return

        try:
            content = p.read_text(encoding="utf-8", errors="replace")
        except Exception as e:
            QMessageBox.critical(self, "Open Error", f"Failed to read file: {e}")
            return

        editor = QPlainTextEdit()
        editor.setFont(QFontDatabase.systemFont(QFontDatabase.FixedFont))
        editor.setPlainText(content)
        editor.setLineWrapMode(QPlainTextEdit.NoWrap)

        ext = p.suffix.lower()
        lang = "python" if ext in (".py", ".pyw") else ("javascript" if ext in (".js", ".ts") else ("xml" if ext in (".xml", ".xaml") else ("json" if ext == ".json" else "generic")))
        highlighter = CodeHighlighter(editor.document(), lang=lang, theme=self.ctx.theme)
        editor._highlighter = highlighter
        editor._file_path = p

        idx = self.editor_tabs.addTab(editor, p.name)
        self.editor_tabs.setCurrentIndex(idx)
        self.open_tabs[key] = editor

    def _close_tab(self, idx: int):
        w = self.editor_tabs.widget(idx)
        if hasattr(w, "_file_path"):
            key = str(w._file_path.resolve())
            if key in self.open_tabs:
                del self.open_tabs[key]
        self.editor_tabs.removeTab(idx)

    def _save_current_file(self):
        w = self.editor_tabs.currentWidget()
        if not w or not hasattr(w, "_file_path"):
            return
        p = w._file_path
        try:
            p.write_text(w.toPlainText(), encoding="utf-8")
            self.ctx.status(f"Saved: {p.name}")
        except Exception as e:
            QMessageBox.critical(self, "Save Error", f"Failed to save file: {e}")

    def _create_new_file(self):
        if not self.reconstructed_dir:
            return
        cur_item = self.file_tree.currentItem()
        target_dir = self.reconstructed_dir
        if cur_item:
            sel_path = Path(cur_item.data(0, Qt.UserRole))
            target_dir = sel_path if sel_path.is_dir() else sel_path.parent

        name, ok = QFileDialog.getSaveFileName(self, "Create New Clean-Room File", str(target_dir / "new_file.py"))
        if ok and name:
            p = Path(name)
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text("", encoding="utf-8")
            self._refresh_file_tree()
            self._open_file(p)

    def _show_diff(self):
        w = self.editor_tabs.currentWidget()
        if not w or not hasattr(w, "_file_path"):
            QMessageBox.information(self, "Diff", "Please open a file to compare.")
            return

        cur_text = w.toPlainText().splitlines(keepends=True)
        file_path = w._file_path

        # Compare with original saved version on disk
        saved_text = file_path.read_text(encoding="utf-8", errors="replace").splitlines(keepends=True)
        diff = difflib.unified_diff(saved_text, cur_text, fromfile=f"saved/{file_path.name}", tofile=f"editor/{file_path.name}")
        diff_str = "".join(diff) or "No changes detected between editor and saved file."

        dlg = QDialog(self)
        dlg.setWindowTitle(f"Diff Viewer: {file_path.name}")
        dlg.resize(750, 480)
        v = QVBoxLayout(dlg)
        ed = QPlainTextEdit()
        ed.setFont(QFontDatabase.systemFont(QFontDatabase.FixedFont))
        ed.setReadOnly(True)
        ed.setPlainText(diff_str)
        v.addWidget(ed)
        btn = QPushButton("Close")
        btn.clicked.connect(dlg.accept)
        v.addWidget(btn)
        dlg.exec()

    # ---- Runner Actions ------------------------------------------------------
    def _run_tests(self):
        if not self.reconstructed_dir:
            return

        # Find project directory (either reconstructed_dir or its first subfolder)
        subdirs = [d for d in self.reconstructed_dir.iterdir() if d.is_dir()]
        target_dir = subdirs[0] if subdirs else self.reconstructed_dir

        self.con_title.setText(f"Running Tests in {target_dir.name}…")
        self.console_output.appendPlainText(f"\n--- [TEST EXECUTION: {target_dir.name}] ---")

        res = run_project_tests(target_dir)

        out = res.stdout + ("\n" + res.stderr if res.stderr else "")
        self.console_output.appendPlainText(out)
        status_msg = f"Tests completed in {res.duration:.2f}s (Exit code: {res.returncode})"
        self.console_output.appendPlainText(f"--- [{status_msg}] ---\n")
        self.con_title.setText(f"Console: {status_msg}")
        self.ctx.status(status_msg)

    def _run_build(self):
        if not self.reconstructed_dir:
            return

        subdirs = [d for d in self.reconstructed_dir.iterdir() if d.is_dir()]
        target_dir = subdirs[0] if subdirs else self.reconstructed_dir

        self.con_title.setText(f"Running Build in {target_dir.name}…")
        self.console_output.appendPlainText(f"\n--- [BUILD EXECUTION: {target_dir.name}] ---")

        res = run_project_build(target_dir)

        out = res.stdout + ("\n" + res.stderr if res.stderr else "")
        self.console_output.appendPlainText(out)
        status_msg = f"Build completed in {res.duration:.2f}s (Exit code: {res.returncode})"
        self.console_output.appendPlainText(f"--- [{status_msg}] ---\n")
        self.con_title.setText(f"Console: {status_msg}")
        self.ctx.status(status_msg)
