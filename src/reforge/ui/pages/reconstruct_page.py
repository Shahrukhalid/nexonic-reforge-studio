"""Reconstruction Studio: clean-room project reconstruction wizard."""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtGui import QFontDatabase
from PySide6.QtWidgets import (
    QComboBox,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QVBoxLayout,
)

from ...reconstruct import scaffold_project
from ...reconstruct.tasks import TaskPlanner
from .common import Page


class ReconstructionStudioPage(Page):
    title = "Reconstruction Studio"
    subtitle = "Develop independent, clean-room implementations based on authorized analysis and documented functional specifications."

    def __init__(self, ctx):
        super().__init__(ctx)
        self.current_pid: int | None = None
        self.features: list[dict] = []
        self.tasks: list[dict] = []
        self.reviews: list[dict] = []

        # Top Project Selector Bar
        top = QHBoxLayout()
        top.addWidget(QLabel("Project:"))
        self.proj_sel = QComboBox()
        self.proj_sel.currentIndexChanged.connect(self._on_project_changed)
        top.addWidget(self.proj_sel, 1)

        self.lbl_status = QLabel("")
        self.lbl_status.setObjectName("Muted")
        top.addWidget(self.lbl_status)

        self.root.addLayout(top)

        # Main Reconstruction Wizard Steps (in tabs)
        self.wizard_tabs = QTabWidget()

        # Step 1: Feature Discovery & Selection
        step1 = QFrame()
        s1_lay = QVBoxLayout(step1)
        s1_lay.setContentsMargins(12, 12, 12, 12)
        s1_lay.addWidget(QLabel("<b>Step 1: Discovered Features & API Contracts</b><br>"
                                "<span style='color: #888;'>Select the features and components you intend to reimplement independently.</span>"))

        self.table_features = QTableWidget(0, 3)
        self.table_features.setHorizontalHeaderLabels(["Select", "Feature / Component", "Category / Evidence"])
        self.table_features.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.table_features.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        s1_lay.addWidget(self.table_features, 1)

        btn_h1 = QHBoxLayout()
        btn_sel_all = QPushButton("Select All")
        btn_sel_all.clicked.connect(self._select_all_features)
        btn_desel_all = QPushButton("Deselect All")
        btn_desel_all.clicked.connect(self._deselect_all_features)
        btn_next1 = QPushButton("Generate Specification ->")
        btn_next1.setObjectName("Primary")
        btn_next1.clicked.connect(lambda: self.wizard_tabs.setCurrentIndex(1))

        btn_h1.addWidget(btn_sel_all)
        btn_h1.addWidget(btn_desel_all)
        btn_h1.addStretch(1)
        btn_h1.addWidget(btn_next1)
        s1_lay.addLayout(btn_h1)

        self.wizard_tabs.addTab(step1, "1. Features & APIs")

        # Step 2: Functional Specification Generation
        step2 = QFrame()
        s2_lay = QVBoxLayout(step2)
        s2_lay.setContentsMargins(12, 12, 12, 12)
        s2_lay.addWidget(QLabel("<b>Step 2: Clean-Room Functional Specification</b><br>"
                                "<span style='color: #888;'>Documented requirements and interface contracts without proprietary implementation code.</span>"))

        self.txt_spec = QPlainTextEdit()
        self.txt_spec.setFont(QFontDatabase.systemFont(QFontDatabase.FixedFont))
        s2_lay.addWidget(self.txt_spec, 1)

        btn_h2 = QHBoxLayout()
        btn_regen_spec = QPushButton("Regenerate Spec")
        btn_regen_spec.clicked.connect(self._generate_spec)
        btn_next2 = QPushButton("Configure Project ->")
        btn_next2.setObjectName("Primary")
        btn_next2.clicked.connect(lambda: self.wizard_tabs.setCurrentIndex(2))

        btn_h2.addWidget(btn_regen_spec)
        btn_h2.addStretch(1)
        btn_h2.addWidget(btn_next2)
        s2_lay.addLayout(btn_h2)

        self.wizard_tabs.addTab(step2, "2. Specification")

        # Step 3: Target Architecture & Scaffolding
        step3 = QFrame()
        s3_lay = QVBoxLayout(step3)
        s3_lay.setContentsMargins(12, 12, 12, 12)
        s3_lay.setSpacing(12)

        s3_lay.addWidget(QLabel("<b>Step 3: Target Architecture & Project Generation</b>"))

        # Config Card
        cfg_card = QFrame()
        cfg_card.setObjectName("Card")
        cfg_lay = QVBoxLayout(cfg_card)
        cfg_lay.setContentsMargins(16, 14, 16, 14)
        cfg_lay.setSpacing(10)

        # Project Name
        cfg_lay.addWidget(QLabel("New Project Name:"))
        self.txt_proj_name = QLineEdit("reconstructed_app")
        cfg_lay.addWidget(self.txt_proj_name)

        # Target Language
        cfg_lay.addWidget(QLabel("Target Language & Stack:"))
        self.sel_stack = QComboBox()
        self.sel_stack.addItems(["Python (FastAPI / Standard)", "TypeScript (Node.js)", "Rust", "Go", "C# (.NET 8)"])
        cfg_lay.addWidget(self.sel_stack)

        # License
        cfg_lay.addWidget(QLabel("Clean-Room Project License:"))
        self.sel_license = QComboBox()
        self.sel_license.addItems(["MIT", "Apache-2.0", "BSD-3-Clause", "Proprietary"])
        cfg_lay.addWidget(self.sel_license)

        s3_lay.addWidget(cfg_card)

        # Notice
        lbl_notice = QLabel("Clean-room rule: Generated projects are written strictly into the project's 'reconstructed/' "
                            "directory, kept completely isolated from extracted or decompiled binary artifacts.")
        lbl_notice.setWordWrap(True)
        lbl_notice.setObjectName("Muted")
        s3_lay.addWidget(lbl_notice)

        s3_lay.addStretch(1)

        btn_h3 = QHBoxLayout()
        self.btn_scaffold = QPushButton("Scaffold Clean-Room Project")
        self.btn_scaffold.setObjectName("Primary")
        self.btn_scaffold.clicked.connect(self._scaffold_project)

        btn_next3 = QPushButton("Implementation Tasks ->")
        btn_next3.clicked.connect(lambda: self.wizard_tabs.setCurrentIndex(3))

        btn_h3.addWidget(self.btn_scaffold)
        btn_h3.addWidget(btn_next3)
        s3_lay.addLayout(btn_h3)

        self.wizard_tabs.addTab(step3, "3. Scaffolding & Generation")

        # Step 4: Implementation Tasks & Human Review Checklist
        step4 = QFrame()
        s4_lay = QVBoxLayout(step4)
        s4_lay.setContentsMargins(12, 12, 12, 12)
        s4_lay.setSpacing(10)

        s4_lay.addWidget(QLabel("<b>Step 4: Implementation Tasks & Human Review Checklist</b><br>"
                                "<span style='color: #888;'>Discrete implementation tasks mapped strictly to confirmed findings, "
                                "with explicit human review items for unknown or tentative boundaries.</span>"))

        # Tasks Table
        s4_lay.addWidget(QLabel("<b>Discrete Implementation Tasks</b>"))
        self.table_tasks = QTableWidget(0, 5)
        self.table_tasks.setHorizontalHeaderLabels(["Task ID", "Category", "Task Title", "Human Review", "Status"])
        self.table_tasks.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        s4_lay.addWidget(self.table_tasks, 2)

        # Human Review Checklist Table
        s4_lay.addWidget(QLabel("<b>Operator Human Review Checklist (Unknowns & Unverified Contracts)</b>"))
        self.table_reviews = QTableWidget(0, 4)
        self.table_reviews.setHorizontalHeaderLabels(["ID", "Review Item", "Status Category", "Recommended Operator Action"])
        self.table_reviews.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.table_reviews.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        s4_lay.addWidget(self.table_reviews, 2)

        # Scaffolding != Reconstruction Banner
        lbl_rule = QLabel(
            "⚠️ Clean-Room Rule: Scaffolding generation does NOT equal complete application reconstruction. "
            "Manual engineering review, verified business logic, and independent domain implementation are strictly required."
        )
        lbl_rule.setWordWrap(True)
        lbl_rule.setStyleSheet("color: #d19a66; font-weight: bold; padding: 4px;")
        s4_lay.addWidget(lbl_rule)

        btn_h4 = QHBoxLayout()
        btn_plan_tasks = QPushButton("Refresh Tasks & Checklist")
        btn_plan_tasks.clicked.connect(self._generate_tasks)

        self.btn_run_tests = QPushButton("Run Clean-Room Behavioral Tests")
        self.btn_run_tests.clicked.connect(self._run_tests)

        self.btn_open_ws = QPushButton("Open in Source Workspace ->")
        self.btn_open_ws.setEnabled(False)
        self.btn_open_ws.clicked.connect(self._open_in_workspace)

        btn_h4.addWidget(btn_plan_tasks)
        btn_h4.addWidget(self.btn_run_tests)
        btn_h4.addStretch(1)
        btn_h4.addWidget(self.btn_open_ws)
        s4_lay.addLayout(btn_h4)

        self.wizard_tabs.addTab(step4, "4. Tasks & Review")

        self.root.addWidget(self.wizard_tabs, 1)

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
            self.table_features.setRowCount(0)
            self.table_tasks.setRowCount(0)
            self.table_reviews.setRowCount(0)
            self.txt_spec.setPlainText("")

    def _on_project_changed(self, _idx: int):
        pid = self.proj_sel.currentData()
        if pid:
            self._load_project(pid)

    def _load_project(self, pid: int):
        self.current_pid = pid
        p = self.ctx.db.project(pid)
        if not p:
            return

        self.txt_proj_name.setText(f"{p['name'].lower().replace('.', '_')}_reforge")

        # Discover features from findings
        rows = self.ctx.db.findings(pid)
        self.features.clear()

        # Network endpoints
        for r in rows:
            if r["kind"] == "network" and isinstance(r["value"], list):
                for u in r["value"]:
                    self.features.append({
                        "name": f"API Endpoint: {u}",
                        "category": "Networking",
                        "raw": u,
                    })
            elif r["key"] == "android_manifest" and isinstance(r["value"], dict):
                for act in r["value"].get("components", {}).get("activities", []):
                    self.features.append({
                        "name": f"Activity Screen: {act.get('name')}",
                        "category": "User Interface",
                        "raw": act,
                    })
            elif r["key"] == "package_json" and isinstance(r["value"], dict):
                for dep, ver in r["value"].get("dependencies", {}).items():
                    self.features.append({
                        "name": f"Service Integration: {dep} ({ver})",
                        "category": "External Dependency",
                        "raw": dep,
                    })

        if not self.features:
            self.features.append({
                "name": "Core Application Logic",
                "category": "Application Service",
                "raw": "core"
            })

        self.table_features.setRowCount(len(self.features))
        for row, feat in enumerate(self.features):
            chk = QTableWidgetItem()
            chk.setFlags(Qt.ItemIsUserCheckable | Qt.ItemIsEnabled)
            chk.setCheckState(Qt.Checked)
            self.table_features.setItem(row, 0, chk)
            self.table_features.setItem(row, 1, QTableWidgetItem(feat["name"]))
            self.table_features.setItem(row, 2, QTableWidgetItem(feat["category"]))

        self._generate_spec()
        self._generate_tasks()

    def _select_all_features(self):
        for i in range(self.table_features.rowCount()):
            item = self.table_features.item(i, 0)
            if item:
                item.setCheckState(Qt.Checked)
        self._generate_spec()
        self._generate_tasks()

    def _deselect_all_features(self):
        for i in range(self.table_features.rowCount()):
            item = self.table_features.item(i, 0)
            if item:
                item.setCheckState(Qt.Unchecked)
        self._generate_spec()
        self._generate_tasks()

    def _generate_spec(self):
        pid = self.current_pid
        p = self.ctx.db.project(pid) if pid else None
        p_name = p["name"] if p else "Target Application"

        selected_feats = []
        for i in range(self.table_features.rowCount()):
            item = self.table_features.item(i, 0)
            if item and item.checkState() == Qt.Checked:
                selected_feats.append(self.features[i])

        lines = [
            f"# Functional Requirements Specification: {p_name}",
            "\n## 1. Clean-Room Implementation Mandate",
            "This document establishes the functional requirements for an independent, clean-room reimplementation.",
            "Developers working on this implementation must NOT refer to decompiled or disassembled proprietary binaries.",
            "\n## 2. Selected Feature Requirements",
        ]

        for idx, sf in enumerate(selected_feats, 1):
            lines.append(f"### 2.{idx} {sf['name']}")
            lines.append(f"- **Category:** {sf['category']}")
            lines.append("- **Requirement:** Implement independent service adhering to interface and protocol specifications.")

        lines.extend([
            "\n## 3. Data Integrity & Verification",
            "- Independent test suites must validate functional parity against documented requirements.",
            "- Verification artifacts must be preserved without proprietary source inclusion.",
        ])

        self.txt_spec.setPlainText("\n".join(lines))

    def _generate_tasks(self):
        pid = self.current_pid
        p = self.ctx.db.project(pid) if pid else None
        p_name = p["name"] if p else "TargetApp"
        spec = self.txt_spec.toPlainText()
        findings = self.ctx.db.findings(pid) if pid else []

        tasks, reviews = TaskPlanner.generate_plan(spec, findings, p_name)
        self.tasks = [t.to_dict() for t in tasks]
        self.reviews = [r.to_dict() for r in reviews]

        # Populate tasks table
        self.table_tasks.setRowCount(len(tasks))
        for row, t in enumerate(tasks):
            self.table_tasks.setItem(row, 0, QTableWidgetItem(t.id))
            self.table_tasks.setItem(row, 1, QTableWidgetItem(t.category))
            self.table_tasks.setItem(row, 2, QTableWidgetItem(t.title))
            rev_label = "MANDATORY" if t.requires_human_review else "NO"
            self.table_tasks.setItem(row, 3, QTableWidgetItem(rev_label))
            self.table_tasks.setItem(row, 4, QTableWidgetItem(t.status.upper()))

        # Populate reviews table
        self.table_reviews.setRowCount(len(reviews))
        for row, r in enumerate(reviews):
            self.table_reviews.setItem(row, 0, QTableWidgetItem(r.id))
            self.table_reviews.setItem(row, 1, QTableWidgetItem(r.item))
            self.table_reviews.setItem(row, 2, QTableWidgetItem(r.evidence_status))
            self.table_reviews.setItem(row, 3, QTableWidgetItem(r.recommended_action))

    def _scaffold_project(self):
        pid = self.current_pid
        p = self.ctx.db.project(pid) if pid else None
        if not p or not p.get("workdir"):
            QMessageBox.warning(self, "Scaffold", "Please select a valid project first.")
            return

        proj_name = self.txt_proj_name.text().strip() or "reconstructed_app"
        stack_raw = self.sel_stack.currentText()
        stack = "python" if "Python" in stack_raw else ("typescript" if "TypeScript" in stack_raw else ("rust" if "Rust" in stack_raw else ("go" if "Go" in stack_raw else "csharp")))
        lic = self.sel_license.currentText()
        spec_text = self.txt_spec.toPlainText()

        dest_dir = Path(p["workdir"]) / "reconstructed" / proj_name

        created_files = scaffold_project(
            dest_dir=dest_dir,
            project_name=proj_name,
            stack=stack,
            features=self.features,
            spec_md=spec_text,
            license_type=lic,
        )

        self.ctx.status(f"Scaffolded {len(created_files)} files to {dest_dir}")
        QMessageBox.information(self, "Project Scaffolded",
                                f"Clean-room project '{proj_name}' created successfully with {len(created_files)} files at:\n{dest_dir}")
        self.btn_open_ws.setEnabled(True)
        self._generate_tasks()

    def _run_tests(self):
        pid = self.current_pid
        p = self.ctx.db.project(pid) if pid else None
        if not p or not p.get("workdir"):
            QMessageBox.warning(self, "Run Tests", "Please select a project with a valid workspace.")
            return

        proj_name = self.txt_proj_name.text().strip() or "reconstructed_app"
        dest_dir = Path(p["workdir"]) / "reconstructed" / proj_name
        test_file = dest_dir / "tests" / "test_behavioral.py"

        if not test_file.exists():
            QMessageBox.information(self, "Run Tests", f"No generated Python tests found at:\n{test_file}\nScaffold the project first.")
            return

        # Run tests safely using unittest in an isolated subprocess
        res = subprocess.run([sys.executable, "-m", "unittest", str(test_file)], capture_output=True, text=True)
        outcome = "PASSED" if res.returncode == 0 else "FAILURES DETECTED"
        msg = f"Test Execution Outcome: {outcome}\n\nSTDOUT:\n{res.stdout}\nSTDERR:\n{res.stderr}"
        if res.returncode == 0:
            QMessageBox.information(self, "Behavioral Tests", msg)
        else:
            QMessageBox.warning(self, "Behavioral Tests", msg)

    def _open_in_workspace(self):
        self.ctx.window.show_page("Source Code Workspace", select=self.current_pid)
