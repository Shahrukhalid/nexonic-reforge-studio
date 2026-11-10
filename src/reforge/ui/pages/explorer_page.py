"""Application Explorer: hierarchical structure, dependencies, symbols, endpoints, and code viewer."""
from __future__ import annotations

import json

from PySide6.QtCore import Qt
from PySide6.QtGui import QFontDatabase
from PySide6.QtWidgets import (
    QComboBox,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
)

from ..highlighter import CodeHighlighter
from .common import Page


class ApplicationExplorerPage(Page):
    title = "Application Explorer"
    subtitle = "Hierarchical application structure, symbols, dependencies, endpoints, and decompiled code."

    def __init__(self, ctx):
        super().__init__(ctx)
        self.current_pid: int | None = None

        # Top bar: project selection, tech badges, search
        top = QHBoxLayout()
        top.addWidget(QLabel("Project:"))
        self.proj_sel = QComboBox()
        self.proj_sel.currentIndexChanged.connect(self._on_project_changed)
        top.addWidget(self.proj_sel, 1)

        self.tech_container = QHBoxLayout()
        top.addLayout(self.tech_container)

        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Search symbols, classes, endpoints…")
        self.search_input.textChanged.connect(self._apply_search)
        top.addWidget(self.search_input, 1)

        self.root.addLayout(top)

        # Main splitter: Left navigation tabs, Right detail & code viewer
        split = QSplitter(Qt.Horizontal)

        # Left panel: tabs
        self.tabs = QTabWidget()

        # Tab 1: Structure (Modules, Classes, Functions, Sections)
        self.tree_struct = QTreeWidget()
        self.tree_struct.setHeaderLabels(["Component", "Type / Size", "Confidence"])
        self.tree_struct.header().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.tree_struct.currentItemChanged.connect(self._on_struct_selected)
        self.tabs.addTab(self.tree_struct, "Structure")

        # Tab 2: Dependencies & Imports
        self.table_deps = QTableWidget(0, 3)
        self.table_deps.setHorizontalHeaderLabels(["Library / Package", "Symbol / Spec", "Category"])
        self.table_deps.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.table_deps.setSelectionBehavior(QTableWidget.SelectRows)
        self.table_deps.currentItemChanged.connect(self._on_dep_selected)
        self.tabs.addTab(self.table_deps, "Dependencies")

        # Tab 3: Endpoints & Network
        self.table_endpoints = QTableWidget(0, 3)
        self.table_endpoints.setHorizontalHeaderLabels(["Indicator / URL", "Type", "Confidence"])
        self.table_endpoints.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.table_endpoints.setSelectionBehavior(QTableWidget.SelectRows)
        self.table_endpoints.currentItemChanged.connect(self._on_endpoint_selected)
        self.tabs.addTab(self.table_endpoints, "Endpoints")

        # Tab 4: Strings & Config
        self.table_strings = QTableWidget(0, 3)
        self.table_strings.setHorizontalHeaderLabels(["Value", "Category", "Confidence"])
        self.table_strings.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.table_strings.setSelectionBehavior(QTableWidget.SelectRows)
        self.table_strings.currentItemChanged.connect(self._on_string_selected)
        self.tabs.addTab(self.table_strings, "Strings & Config")

        # Tab 5: Call Graph & Functions
        self.tree_calls = QTreeWidget()
        self.tree_calls.setHeaderLabels(["Function", "Calls / Direction", "Offset"])
        self.tree_calls.header().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.tree_calls.currentItemChanged.connect(self._on_call_selected)
        self.tabs.addTab(self.tree_calls, "Call Graph")

        split.addWidget(self.tabs)

        # Right panel: Code / Detail Inspector
        right = QFrame()
        right_lay = QVBoxLayout(right)
        right_lay.setContentsMargins(0, 0, 0, 0)
        right_lay.setSpacing(8)

        # Header card showing selected item info and provenance banner
        self.banner = QFrame()
        self.banner.setObjectName("Card")
        ban_lay = QHBoxLayout(self.banner)
        ban_lay.setContentsMargins(12, 8, 12, 8)

        self.lbl_title = QLabel("Select an item to inspect")
        self.lbl_title.setStyleSheet("font-weight: 600; font-size: 13px;")
        ban_lay.addWidget(self.lbl_title)
        ban_lay.addStretch(1)

        self.lbl_prov = QLabel("")
        self.lbl_prov.setStyleSheet("background-color: #2b3a4a; color: #61afef; padding: 3px 8px; border-radius: 4px; font-weight: bold;")
        ban_lay.addWidget(self.lbl_prov)

        self.lbl_conf = QLabel("")
        self.lbl_conf.setStyleSheet("background-color: #3b3a2a; color: #e5c07b; padding: 3px 8px; border-radius: 4px; font-weight: bold;")
        ban_lay.addWidget(self.lbl_conf)

        right_lay.addWidget(self.banner)

        # Viewer tabs: Code view vs Metadata view
        self.view_tabs = QTabWidget()

        # Code Viewer
        code_w = QFrame()
        code_lay = QVBoxLayout(code_w)
        code_lay.setContentsMargins(0, 0, 0, 0)

        self.code_edit = QPlainTextEdit()
        self.code_edit.setReadOnly(True)
        self.code_edit.setFont(QFontDatabase.systemFont(QFontDatabase.FixedFont))
        self.code_edit.setLineWrapMode(QPlainTextEdit.NoWrap)
        self.highlighter = CodeHighlighter(self.code_edit.document(), theme=self.ctx.theme)
        code_lay.addWidget(self.code_edit)

        self.view_tabs.addTab(code_w, "Code / Disassembly")

        # Properties / Metadata Table
        self.prop_table = QTableWidget(0, 2)
        self.prop_table.setHorizontalHeaderLabels(["Property", "Value"])
        self.prop_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.prop_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.view_tabs.addTab(self.prop_table, "Attributes & Evidence")

        right_lay.addWidget(self.view_tabs, 1)
        split.addWidget(right)

        split.setSizes([480, 640])
        self.root.addWidget(split, 1)

    # ---- Lifecycle -----------------------------------------------------------
    def refresh(self, select: int | None = None) -> None:
        self.highlighter.set_theme(self.ctx.theme)
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
            self._clear_all()

    def _on_project_changed(self, idx: int):
        pid = self.proj_sel.currentData()
        if pid:
            self._load_project(pid)

    def _clear_all(self):
        self.current_pid = None
        self.tree_struct.clear()
        self.table_deps.setRowCount(0)
        self.table_endpoints.setRowCount(0)
        self.table_strings.setRowCount(0)
        self.tree_calls.clear()
        self.code_edit.setPlainText("")
        self.prop_table.setRowCount(0)
        self.lbl_title.setText("No project loaded")
        self.lbl_prov.setText("")
        self.lbl_conf.setText("")
        while self.tech_container.count():
            item = self.tech_container.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

    # ---- Data Loading --------------------------------------------------------
    def _load_project(self, pid: int):
        self.current_pid = pid
        self._clear_all()
        self.current_pid = pid

        rows = self.ctx.db.findings(pid)
        p = self.ctx.db.project(pid)

        # 1. Tech badges
        techs = sorted({r["key"] for r in rows if r["kind"] == "technology"})
        for t in techs:
            b = QLabel(t)
            b.setStyleSheet("background-color: #283c2e; color: #98c379; padding: 2px 6px; border-radius: 3px; font-weight: 500;")
            self.tech_container.addWidget(b)

        # 2. Structure Tree
        self._populate_structure(rows, p)

        # 3. Dependencies
        self._populate_deps(rows)

        # 4. Endpoints & Network
        self._populate_endpoints(rows)

        # 5. Strings & Config
        self._populate_strings(rows)

        # 6. Call Graph
        self._populate_callgraph(rows)

    def _populate_structure(self, rows: list[dict], proj: dict | None):
        self.tree_struct.clear()

        # Binary sections & headers
        bin_items = [r for r in rows if r["stage"] == "binary"]
        if bin_items:
            root_bin = QTreeWidgetItem(self.tree_struct, ["Binary Structure", f"{len(bin_items)} sections/headers", "Confirmed"])
            for r in bin_items:
                child = QTreeWidgetItem(root_bin, [r["key"], r.get("subject", ""), r["confidence"]])
                child.setData(0, Qt.UserRole, r)

        # Decompiled / Disassembled code & Functions
        code_items = [r for r in rows if r["stage"] in ("decompiled", "disasm", "tools") and r["kind"] in ("decompiled", "disasm", "functions")]
        if code_items:
            root_code = QTreeWidgetItem(self.tree_struct, ["Code & Functions", f"{len(code_items)} items", "Decompiled/Disasm"])
            for r in code_items:
                name = r.get("subject") or r.get("key") or "function"
                child = QTreeWidgetItem(root_code, [name, r["kind"], r["confidence"]])
                child.setData(0, Qt.UserRole, r)

        # Package / Inventory Structure
        inv_items = [r for r in rows if r["stage"] in ("inventory", "extract")]
        if inv_items:
            root_inv = QTreeWidgetItem(self.tree_struct, ["Package Layout", f"{len(inv_items)} catalogs", "Extracted"])
            for r in inv_items:
                child = QTreeWidgetItem(root_inv, [r["key"], r.get("subject", ""), r["confidence"]])
                child.setData(0, Qt.UserRole, r)

        self.tree_struct.expandAll()

    def _populate_deps(self, rows: list[dict]):
        self.table_deps.setRowCount(0)
        items = []
        for r in rows:
            v = r["value"]
            if r["key"] == "libraries" and isinstance(v, list):
                for lib in v:
                    items.append((lib, "Dynamic Link", "Native Library"))
            elif r["key"] == "imported_symbols" and isinstance(v, list):
                for sym in v[:200]:
                    items.append((sym.get("library", "Import"), sym.get("name", ""), "Symbol"))
            elif r["key"] == "package_json" and isinstance(v, dict):
                for pkg, ver in v.get("dependencies", {}).items():
                    items.append((pkg, ver, "npm dependency"))
            elif r["key"] == "dotnet_metadata" and isinstance(v, dict):
                for ref in v.get("assembly_refs", []):
                    items.append((ref.get("name", ""), ref.get("version", ""), ".NET Reference"))
            elif r["key"] == "apk_contents" and isinstance(v, dict):
                for abi in v.get("native_abis", []):
                    items.append(("Android ABI", abi, "Architecture Target"))

        self.table_deps.setRowCount(len(items))
        for row, (col0, col1, col2) in enumerate(items):
            self.table_deps.setItem(row, 0, QTableWidgetItem(str(col0)))
            self.table_deps.setItem(row, 1, QTableWidgetItem(str(col1)))
            self.table_deps.setItem(row, 2, QTableWidgetItem(str(col2)))

    def _populate_endpoints(self, rows: list[dict]):
        self.table_endpoints.setRowCount(0)
        items = []
        for r in rows:
            if r["kind"] == "network" and isinstance(r["value"], list):
                for val in r["value"]:
                    items.append((val, r["key"], r["confidence"], r))
        self.table_endpoints.setRowCount(len(items))
        for row, (val, typ, conf, raw) in enumerate(items):
            self.table_endpoints.setItem(row, 0, QTableWidgetItem(str(val)))
            self.table_endpoints.setItem(row, 1, QTableWidgetItem(str(typ)))
            self.table_endpoints.setItem(row, 2, QTableWidgetItem(str(conf)))
            self.table_endpoints.item(row, 0).setData(Qt.UserRole, raw)

    def _populate_strings(self, rows: list[dict]):
        self.table_strings.setRowCount(0)
        items = []
        for r in rows:
            if r["stage"] == "strings" and r["kind"] != "network" and isinstance(r["value"], list):
                for val in r["value"]:
                    items.append((val, r["key"], r["confidence"], r))
        self.table_strings.setRowCount(len(items))
        for row, (val, cat, conf, raw) in enumerate(items):
            self.table_strings.setItem(row, 0, QTableWidgetItem(str(val)))
            self.table_strings.setItem(row, 1, QTableWidgetItem(str(cat)))
            self.table_strings.setItem(row, 2, QTableWidgetItem(str(conf)))
            self.table_strings.item(row, 0).setData(Qt.UserRole, raw)

    def _populate_callgraph(self, rows: list[dict]):
        self.tree_calls.clear()
        ghidra_runs = [r for r in rows if r["tool"] == "Ghidra" and r["key"] == "call_graph"]
        if ghidra_runs:
            for r in ghidra_runs:
                cg = r["value"]
                if isinstance(cg, dict):
                    for caller, callees in list(cg.items())[:100]:
                        item = QTreeWidgetItem(self.tree_calls, [caller, f"Calls {len(callees)} targets", ""])
                        item.setData(0, Qt.UserRole, r)
                        for c in callees:
                            sub = QTreeWidgetItem(item, [c, "-> Callee", ""])
                            sub.setData(0, Qt.UserRole, r)
        else:
            # Fallback to disassembly entry points
            disasm_runs = [r for r in rows if r["stage"] == "disasm"]
            for r in disasm_runs:
                v = r["value"]
                if isinstance(v, dict):
                    item = QTreeWidgetItem(self.tree_calls, [v.get("function", r["key"]), "Entry / Export", v.get("address", "")])
                    item.setData(0, Qt.UserRole, r)

    # ---- Selection Handlers --------------------------------------------------
    def _on_struct_selected(self, cur: QTreeWidgetItem, _prev):
        if not cur:
            return
        r = cur.data(0, Qt.UserRole)
        if r:
            self._display_finding(r)

    def _on_dep_selected(self, cur: QTableWidgetItem, _prev):
        if not cur:
            return
        row = cur.row()
        lib = self.table_deps.item(row, 0).text()
        sym = self.table_deps.item(row, 1).text()
        cat = self.table_deps.item(row, 2).text()
        self.lbl_title.setText(f"Dependency: {lib} ({sym})")
        self.lbl_prov.setText("PARSED STRUCTURE")
        self.lbl_conf.setText("CONFIRMED")
        self.code_edit.setPlainText(f"// Dependency Reference\nLibrary / Package: {lib}\nSymbol / Specification: {sym}\nCategory: {cat}\n")
        self._set_props({"Library": lib, "Symbol": sym, "Category": cat})

    def _on_endpoint_selected(self, cur: QTableWidgetItem, _prev):
        if not cur:
            return
        r = self.table_endpoints.item(cur.row(), 0).data(Qt.UserRole)
        if r:
            self._display_finding(r)

    def _on_string_selected(self, cur: QTableWidgetItem, _prev):
        if not cur:
            return
        r = self.table_strings.item(cur.row(), 0).data(Qt.UserRole)
        if r:
            self._display_finding(r)

    def _on_call_selected(self, cur: QTreeWidgetItem, _prev):
        if not cur:
            return
        r = cur.data(0, Qt.UserRole)
        func_name = cur.text(0)
        self.lbl_title.setText(f"Function: {func_name}")
        self.lbl_prov.setText("PARSED CALL GRAPH")
        self.lbl_conf.setText("CONFIRMED")
        if r:
            self._display_finding(r)

    # ---- Display Details -----------------------------------------------------
    def _display_finding(self, r: dict):
        key = r.get("key", "")
        subj = r.get("subject", "")
        self.lbl_title.setText(f"{r.get('kind', 'finding').upper()}: {key} {('(' + subj + ')') if subj else ''}")

        prov = str(r.get("provenance", "parsed_structure")).upper().replace("_", " ")
        conf = str(r.get("confidence", "confirmed")).upper()

        self.lbl_prov.setText(f"PROVENANCE: {prov}")
        self.lbl_conf.setText(f"CONFIDENCE: {conf}")

        val = r.get("value")
        text = ""
        lang = "generic"

        if isinstance(val, dict):
            if "code" in val:
                text = val["code"]
                if key.endswith((".java", "jadx")):
                    lang = "java"
                elif key.endswith((".cs", "ilspy")):
                    lang = "csharp"
                elif key.endswith((".py", "pyc", "pycdc")):
                    lang = "python"
                elif key.endswith(".js"):
                    lang = "javascript"
            elif "asm" in val or "instructions" in val:
                insts = val.get("instructions") or val.get("asm")
                text = "\n".join(f"{i.get('addr', ''):<16} {i.get('mnemonic', ''):<8} {i.get('op_str', '')}" for i in insts) if isinstance(insts, list) else str(insts)
                lang = "generic"
            elif "xml" in val:
                text = val["xml"]
                lang = "xml"
            else:
                text = json.dumps(val, indent=2)
                lang = "json"
        elif isinstance(val, list):
            text = "\n".join(str(x) for x in val)
        else:
            text = str(val)

        self.highlighter.set_language(lang)
        self.code_edit.setPlainText(text)

        props = {
            "Stage": r.get("stage"),
            "Tool": r.get("tool"),
            "Kind": r.get("kind"),
            "Key": r.get("key"),
            "Subject": r.get("subject"),
            "Confidence": r.get("confidence"),
            "Provenance": r.get("provenance"),
            "Evidence": r.get("evidence"),
        }
        self._set_props(props)

    def _set_props(self, props: dict):
        self.prop_table.setRowCount(len(props))
        for row, (k, v) in enumerate(props.items()):
            self.prop_table.setItem(row, 0, QTableWidgetItem(str(k)))
            self.prop_table.setItem(row, 1, QTableWidgetItem(str(v)))

    def _apply_search(self, q: str):
        q = q.strip().lower()
        if not q:
            # Show all
            for i in range(self.table_deps.rowCount()):
                self.table_deps.setRowHidden(i, False)
            for i in range(self.table_endpoints.rowCount()):
                self.table_endpoints.setRowHidden(i, False)
            for i in range(self.table_strings.rowCount()):
                self.table_strings.setRowHidden(i, False)
            return

        for i in range(self.table_deps.rowCount()):
            match = q in self.table_deps.item(i, 0).text().lower() or q in self.table_deps.item(i, 1).text().lower()
            self.table_deps.setRowHidden(i, not match)

        for i in range(self.table_endpoints.rowCount()):
            match = q in self.table_endpoints.item(i, 0).text().lower()
            self.table_endpoints.setRowHidden(i, not match)

        for i in range(self.table_strings.rowCount()):
            match = q in self.table_strings.item(i, 0).text().lower()
            self.table_strings.setRowHidden(i, not match)
