"""Application Explorer: hierarchical structure, dependencies, symbols, endpoints, and code viewer."""
from __future__ import annotations

import json
import re
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtGui import QFontDatabase
from PySide6.QtWidgets import (
    QApplication,
    QComboBox,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
)

from ...analysis.diffing import BinaryDiffEngine, DiffResult, FunctionDiffItem
from ..highlighter import CodeHighlighter
from .common import Page


class ApplicationExplorerPage(Page):
    title = "Application Explorer"
    subtitle = "Hierarchical application structure, symbols, dependencies, endpoints, and decompiled code."

    def __init__(self, ctx):
        super().__init__(ctx)
        self.current_pid: int | None = None
        self.current_diff_result: DiffResult | None = None
        self.filtered_diff_items: list[FunctionDiffItem] = []
        self.current_pseudo_code: str = ""
        self.current_asm_code: str = ""
        self.current_xrefs_code: str = ""

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

        # Tab 6: Binary Diff
        diff_w = QFrame()
        diff_lay = QVBoxLayout(diff_w)
        diff_lay.setContentsMargins(6, 6, 6, 6)
        diff_lay.setSpacing(6)

        top_diff = QHBoxLayout()
        top_diff.addWidget(QLabel("Compare Target A with:"))
        self.diff_proj_sel = QComboBox()
        top_diff.addWidget(self.diff_proj_sel, 1)

        self.btn_run_diff = QPushButton("Run Binary Diff")
        self.btn_run_diff.clicked.connect(self._on_run_binary_diff)
        top_diff.addWidget(self.btn_run_diff)

        self.btn_export_diff = QPushButton("Export Report…")
        self.btn_export_diff.clicked.connect(self._export_diff_report)
        top_diff.addWidget(self.btn_export_diff)
        diff_lay.addLayout(top_diff)

        self.lbl_diff_summary = QLabel("Select another project above and click 'Run Binary Diff'.")
        self.lbl_diff_summary.setStyleSheet("font-weight: 600; padding: 4px; background-color: #2b3a4a; border-radius: 4px;")
        diff_lay.addWidget(self.lbl_diff_summary)

        filt_lay = QHBoxLayout()
        filt_lay.addWidget(QLabel("Filter:"))
        self.diff_filter = QComboBox()
        self.diff_filter.addItems(["All Functions", "Modified Only", "Added Only", "Removed Only", "Identical Only"])
        self.diff_filter.currentIndexChanged.connect(self._apply_diff_filter)
        filt_lay.addWidget(self.diff_filter, 1)
        diff_lay.addLayout(filt_lay)

        self.diff_table = QTableWidget(0, 5)
        self.diff_table.setHorizontalHeaderLabels(["Function", "Target A Addr", "Target B Addr", "Status", "Similarity"])
        self.diff_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.diff_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.diff_table.currentItemChanged.connect(self._on_diff_item_selected)
        diff_lay.addWidget(self.diff_table, 2)

        side_split = QSplitter(Qt.Horizontal)

        left_side = QFrame()
        left_lay = QVBoxLayout(left_side)
        left_lay.setContentsMargins(0, 0, 0, 0)
        self.lbl_diff_a = QLabel("Target A (Active Project)")
        self.lbl_diff_a.setStyleSheet("font-weight: bold;")
        left_lay.addWidget(self.lbl_diff_a)
        self.diff_edit_a = QPlainTextEdit()
        self.diff_edit_a.setReadOnly(True)
        self.diff_edit_a.setFont(QFontDatabase.systemFont(QFontDatabase.FixedFont))
        self.diff_highlighter_a = CodeHighlighter(self.diff_edit_a, theme=self.ctx.theme)
        left_lay.addWidget(self.diff_edit_a)
        side_split.addWidget(left_side)

        right_side = QFrame()
        right_lay = QVBoxLayout(right_side)
        right_lay.setContentsMargins(0, 0, 0, 0)
        self.lbl_diff_b = QLabel("Target B (Comparison Target)")
        self.lbl_diff_b.setStyleSheet("font-weight: bold;")
        right_lay.addWidget(self.lbl_diff_b)
        self.diff_edit_b = QPlainTextEdit()
        self.diff_edit_b.setReadOnly(True)
        self.diff_edit_b.setFont(QFontDatabase.systemFont(QFontDatabase.FixedFont))
        self.diff_highlighter_b = CodeHighlighter(self.diff_edit_b, theme=self.ctx.theme)
        right_lay.addWidget(self.diff_edit_b)
        side_split.addWidget(right_side)

        # Synchronized vertical scrolling
        self.diff_edit_a.verticalScrollBar().valueChanged.connect(self._sync_scroll_b)
        self.diff_edit_b.verticalScrollBar().valueChanged.connect(self._sync_scroll_a)

        diff_lay.addWidget(side_split, 3)
        self.tabs.addTab(diff_w, "Binary Diff")

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
        code_lay.setSpacing(4)

        code_bar = QHBoxLayout()
        self.btn_view_pseudo = QPushButton("Pseudocode")
        self.btn_view_pseudo.clicked.connect(lambda: self._switch_code_view("pseudocode"))
        self.btn_view_asm = QPushButton("Assembly")
        self.btn_view_asm.clicked.connect(lambda: self._switch_code_view("assembly"))
        self.btn_view_xrefs = QPushButton("Callers / Callees")
        self.btn_view_xrefs.clicked.connect(lambda: self._switch_code_view("xrefs"))
        code_bar.addWidget(self.btn_view_pseudo)
        code_bar.addWidget(self.btn_view_asm)
        code_bar.addWidget(self.btn_view_xrefs)
        code_bar.addStretch(1)
        btn_copy = QPushButton("Copy Code")
        btn_copy.clicked.connect(self._copy_code)
        btn_save = QPushButton("Save Code to File…")
        btn_save.clicked.connect(self._save_code_to_file)
        code_bar.addWidget(btn_copy)
        code_bar.addWidget(btn_save)
        code_lay.addLayout(code_bar)

        self.code_edit = QPlainTextEdit()
        self.code_edit.setReadOnly(True)
        self.code_edit.setFont(QFontDatabase.systemFont(QFontDatabase.FixedFont))
        self.code_edit.setLineWrapMode(QPlainTextEdit.NoWrap)
        self.highlighter = CodeHighlighter(self.code_edit, theme=self.ctx.theme)
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
        self.diff_proj_sel.blockSignals(True)
        self.diff_proj_sel.clear()
        for p in projs:
            self.diff_proj_sel.addItem(f"#{p['id']} · {p['name']}", p["id"])
        self.diff_proj_sel.blockSignals(False)
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
            w = item.widget() if item else None
            if w:
                w.setParent(None)
                w.deleteLater()

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
                    for caller, callees in list(cg.items())[:150]:
                        item = QTreeWidgetItem(self.tree_calls, [caller, f"Calls {len(callees)} targets", ""])
                        item.setData(0, Qt.UserRole, r)
                        for c in callees:
                            sub = QTreeWidgetItem(item, [c, "-> Callee", ""])
                            sub.setData(0, Qt.UserRole, r)
            return

        # Deep static extraction from linear disassembly & imports
        disasm_runs = [r for r in rows if r["stage"] == "disasm"]
        if not disasm_runs:
            return

        # Build symbol map of known addresses and imports
        import_symbols = set()
        for r in rows:
            if r["kind"] == "imports" and isinstance(r["value"], dict) and "items" in r["value"]:
                import_symbols.update(r["value"]["items"])

        func_by_addr: dict[str, dict] = {}
        for r in disasm_runs:
            v = r["value"]
            if isinstance(v, dict) and "address" in v:
                addr_str = str(v["address"]).lower()
                func_by_addr[addr_str] = r
                if addr_str.startswith("0x"):
                    try:
                        func_by_addr[hex(int(addr_str, 16)).lower()] = r
                    except ValueError:
                        pass

        call_rx = re.compile(r"\b(call|jmp|bl|bx|blx)\s+(0x[0-9a-fA-F]+|[a-zA-Z0-9_]+)\b", re.IGNORECASE)

        for r in disasm_runs:
            v = r["value"]
            if not isinstance(v, dict):
                continue
            fname = v.get("function") or r["key"].replace("disassembly · ", "")
            faddr = v.get("address", "")
            lines = v.get("lines", [])

            callees = []
            for line in lines:
                m = call_rx.search(line)
                if m:
                    inst = m.group(1).lower()
                    target = m.group(2)
                    label = f"-> {inst} {target}"
                    target_finding = func_by_addr.get(target.lower())
                    if target in import_symbols:
                        label += " (Imported API)"
                    elif target_finding:
                        label += f" ({target_finding['key']})"
                    callees.append((target, label, target_finding or r))

            item = QTreeWidgetItem(self.tree_calls, [fname, f"{len(callees)} branch/call targets" if callees else "Leaf function", faddr])
            item.setData(0, Qt.UserRole, r)
            for target, label, finding_ref in callees:
                sub = QTreeWidgetItem(item, [target, label, ""])
                sub.setData(0, Qt.UserRole, finding_ref)

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

        self.current_pseudo_code = ""
        self.current_asm_code = ""
        self.current_xrefs_code = ""

        if isinstance(val, dict):
            if "code" in val:
                text = val["code"]
                self.current_pseudo_code = text
                if key.endswith((".java", "jadx")):
                    lang = "java"
                elif key.endswith((".cs", "ilspy")):
                    lang = "csharp"
                elif key.endswith((".py", "pyc", "pycdc")):
                    lang = "python"
                elif key.endswith(".js"):
                    lang = "javascript"
                else:
                    lang = "c"
            elif "lines" in val and isinstance(val["lines"], list):
                text = "\n".join(val["lines"])
                self.current_asm_code = text
                lang = "asm"
            elif "asm" in val or "instructions" in val:
                insts = val.get("instructions") or val.get("asm")
                text = "\n".join(f"{i.get('addr', ''):<16} {i.get('mnemonic', ''):<8} {i.get('op_str', '')}" for i in insts) if isinstance(insts, list) else str(insts)
                self.current_asm_code = text
                lang = "asm"
            elif "xml" in val:
                text = val["xml"]
                lang = "xml"
            else:
                text = json.dumps(val, indent=2)
                lang = "json"

            callers = val.get("callers", [])
            callees = val.get("callees", [])
            if callers or callees:
                self.current_xrefs_code = (
                    f"/* Function Cross-Reference Mapping: {key} */\n"
                    + f"// Callers ({len(callers)}):\n"
                    + "\n".join(f"  <- {c}" for c in callers)
                    + f"\n\n// Callees ({len(callees)}):\n"
                    + "\n".join(f"  -> {c}" for c in callees)
                    + "\n"
                )
        elif isinstance(val, list):
            text = "\n".join(str(x) for x in val)
        else:
            text = str(val)

        if not self.current_pseudo_code:
            self.current_pseudo_code = text
        if not self.current_asm_code and lang == "asm":
            self.current_asm_code = text

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

    def _switch_code_view(self, mode: str):
        if mode == "assembly" and self.current_asm_code:
            self.highlighter.set_language("asm")
            self.code_edit.setPlainText(self.current_asm_code)
        elif mode == "xrefs" and self.current_xrefs_code:
            self.highlighter.set_language("c")
            self.code_edit.setPlainText(self.current_xrefs_code)
        else:
            self.highlighter.set_language("c")
            self.code_edit.setPlainText(self.current_pseudo_code or self.code_edit.toPlainText())

    def _on_run_binary_diff(self):
        if not self.current_pid:
            self.ctx.status("No active project loaded for comparison.")
            return
        target_b_pid = self.diff_proj_sel.currentData()
        if not target_b_pid or target_b_pid == self.current_pid:
            self.ctx.status("Select a different target project for comparison.")
            return

        proj_a = self.ctx.db.project(self.current_pid)
        proj_b = self.ctx.db.project(target_b_pid)
        findings_a = self.ctx.db.findings(self.current_pid)
        findings_b = self.ctx.db.findings(target_b_pid)

        diff = BinaryDiffEngine.compare_findings(
            findings_a=findings_a,
            findings_b=findings_b,
            name_a=proj_a.get("name", f"Project #{self.current_pid}"),
            name_b=proj_b.get("name", f"Project #{target_b_pid}"),
        )
        self.current_diff_result = diff

        summary_text = (
            f"Overall Similarity: {diff.overall_similarity * 100:.1f}% | "
            f"Identical: {diff.summary.get('identical', 0)} | "
            f"Modified: {diff.summary.get('modified', 0)} | "
            f"Added (+): {diff.summary.get('added', 0)} | "
            f"Removed (-): {diff.summary.get('removed', 0)}"
        )
        self.lbl_diff_summary.setText(summary_text)
        self._apply_diff_filter()

    def _apply_diff_filter(self):
        if not getattr(self, "current_diff_result", None):
            return
        filt = self.diff_filter.currentText()
        items = self.current_diff_result.functions

        if filt == "Modified Only":
            items = [f for f in items if f.status == "modified"]
        elif filt == "Added Only":
            items = [f for f in items if f.status == "added"]
        elif filt == "Removed Only":
            items = [f for f in items if f.status == "removed"]
        elif filt == "Identical Only":
            items = [f for f in items if f.status == "identical"]

        self.filtered_diff_items = items
        self.diff_table.setRowCount(len(items))

        for row, item in enumerate(items):
            self.diff_table.setItem(row, 0, QTableWidgetItem(item.name))
            self.diff_table.setItem(row, 1, QTableWidgetItem(item.address_a or "—"))
            self.diff_table.setItem(row, 2, QTableWidgetItem(item.address_b or "—"))
            self.diff_table.setItem(row, 3, QTableWidgetItem(item.status.upper()))
            self.diff_table.setItem(row, 4, QTableWidgetItem(f"{item.similarity * 100:.1f}%"))

    def _sync_scroll_b(self, val: int):
        if hasattr(self, "diff_edit_b") and not self.diff_edit_b.isHidden():
            sb = self.diff_edit_b.verticalScrollBar()
            if sb.value() != val:
                sb.setValue(val)

    def _sync_scroll_a(self, val: int):
        if hasattr(self, "diff_edit_a") and not self.diff_edit_a.isHidden():
            sb = self.diff_edit_a.verticalScrollBar()
            if sb.value() != val:
                sb.setValue(val)

    def _on_diff_item_selected(self, cur: QTableWidgetItem, _prev):
        if not cur or not getattr(self, "current_diff_result", None):
            return
        row = cur.row()
        filtered = getattr(self, "filtered_diff_items", [])
        if 0 <= row < len(filtered):
            item = filtered[row]
            code_a = item.pseudocode_a or ("\n".join(item.assembly_a) if item.assembly_a else "// [NOT PRESENT IN TARGET A]")
            code_b = item.pseudocode_b or ("\n".join(item.assembly_b) if item.assembly_b else "// [NOT PRESENT IN TARGET B]")

            self.diff_highlighter_a.set_language("c" if item.pseudocode_a else "asm")
            self.diff_highlighter_b.set_language("c" if item.pseudocode_b else "asm")
            self.diff_edit_a.setPlainText(code_a)
            self.diff_edit_b.setPlainText(code_b)

    def _export_diff_report(self):
        if not getattr(self, "current_diff_result", None):
            self.ctx.status("Run a binary diff first before exporting.")
            return
        filename, _ = QFileDialog.getSaveFileName(self, "Export Binary Diff Report", "binary_diff_report.md", "Markdown (*.md);;JSON (*.json)")
        if filename:
            fmt = "json" if filename.endswith(".json") else "markdown"
            report_text = BinaryDiffEngine.generate_diff_report(self.current_diff_result, format=fmt)
            Path(filename).write_text(report_text, encoding="utf-8")
            self.ctx.status(f"Exported binary diff report to {filename}")

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

    def _copy_code(self):
        text = self.code_edit.toPlainText()
        if text:
            QApplication.clipboard().setText(text)
            self.ctx.status("Code copied to clipboard.")

    def _save_code_to_file(self):
        text = self.code_edit.toPlainText()
        if not text:
            return
        filename, _ = QFileDialog.getSaveFileName(self, "Save Code to File", "code_snippet.txt")
        if filename:
            Path(filename).write_text(text, encoding="utf-8")
            self.ctx.status(f"Saved code to {filename}")
