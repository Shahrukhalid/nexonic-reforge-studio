"""Visual UI Explorer: inspect extracted UI assets, layouts, styles, and imported screenshots."""
from __future__ import annotations

import shutil
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtGui import QFontDatabase, QImageReader, QPixmap
from PySide6.QtWidgets import (
    QComboBox,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QScrollArea,
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

IMAGE_EXTS = {".png", ".jpg", ".jpeg", ".svg", ".webp", ".ico", ".gif", ".bmp"}
LAYOUT_EXTS = {".xml", ".xaml", ".html", ".htm", ".vue", ".jsx", ".tsx", ".ui", ".qml", ".storyboard", ".xib"}
STYLE_EXTS = {".css", ".scss", ".sass", ".less", ".json"}


class VisualUIExplorerPage(Page):
    title = "Visual UI Explorer"
    subtitle = "Catalog and preview extracted UI layouts, graphics, styles, and user-imported reference screenshots."

    def __init__(self, ctx):
        super().__init__(ctx)
        self.current_pid: int | None = None
        self.extracted_root: Path | None = None
        self.screenshots_dir: Path | None = None

        # Top bar
        top = QHBoxLayout()
        top.addWidget(QLabel("Project:"))
        self.proj_sel = QComboBox()
        self.proj_sel.currentIndexChanged.connect(self._on_project_changed)
        top.addWidget(self.proj_sel, 1)

        self.stats_lbl = QLabel("")
        self.stats_lbl.setObjectName("Muted")
        top.addWidget(self.stats_lbl)

        btn_import_ss = QPushButton("Import Screenshot…")
        btn_import_ss.clicked.connect(self._import_screenshot)
        top.addWidget(btn_import_ss)

        btn_export = QPushButton("Export UI Assets…")
        btn_export.clicked.connect(self._export_assets)
        top.addWidget(btn_export)

        self.filter_box = QLineEdit()
        self.filter_box.setPlaceholderText("Filter UI assets…")
        self.filter_box.textChanged.connect(self._apply_filter)
        top.addWidget(self.filter_box, 1)

        self.root.addLayout(top)

        # Main splitter
        split = QSplitter(Qt.Horizontal)

        # Left panel: Tree of UI Assets categorized
        self.asset_tree = QTreeWidget()
        self.asset_tree.setHeaderLabels(["Asset / Screen", "Format", "Size"])
        self.asset_tree.header().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.asset_tree.currentItemChanged.connect(self._on_asset_selected)
        split.addWidget(self.asset_tree)

        # Right panel: Previews and Screen Evidence Mapping
        right = QFrame()
        right_lay = QVBoxLayout(right)
        right_lay.setContentsMargins(0, 0, 0, 0)
        right_lay.setSpacing(8)

        # Asset Banner
        self.banner = QFrame()
        self.banner.setObjectName("Card")
        ban_lay = QHBoxLayout(self.banner)
        ban_lay.setContentsMargins(12, 8, 12, 8)

        self.lbl_asset_name = QLabel("No asset selected")
        self.lbl_asset_name.setStyleSheet("font-weight: 600; font-size: 13px;")
        ban_lay.addWidget(self.lbl_asset_name)
        ban_lay.addStretch(1)

        self.badge_status = QLabel("")
        self.badge_status.setStyleSheet("background-color: #2b3a4a; color: #61afef; padding: 3px 8px; border-radius: 4px; font-weight: bold;")
        ban_lay.addWidget(self.badge_status)

        btn_export_asset = QPushButton("Export Asset…")
        btn_export_asset.clicked.connect(self._export_selected_asset)
        ban_lay.addWidget(btn_export_asset)

        right_lay.addWidget(self.banner)

        # Tabs: Visual Preview, Text/Layout View, Screen Mapping
        self.view_tabs = QTabWidget()

        # 1. Image Preview
        self.scroll_img = QScrollArea()
        self.scroll_img.setWidgetResizable(True)
        self.scroll_img.setAlignment(Qt.AlignCenter)
        self.lbl_img_preview = QLabel("Select an image to preview")
        self.lbl_img_preview.setAlignment(Qt.AlignCenter)
        self.scroll_img.setWidget(self.lbl_img_preview)
        self.view_tabs.addTab(self.scroll_img, "Visual Preview")

        # 2. Text / Layout Source
        self.txt_preview = QPlainTextEdit()
        self.txt_preview.setReadOnly(True)
        self.txt_preview.setFont(QFontDatabase.systemFont(QFontDatabase.FixedFont))
        self.highlighter = CodeHighlighter(self.txt_preview.document(), theme=self.ctx.theme)
        self.view_tabs.addTab(self.txt_preview, "Layout / Style Source")

        # 3. Screen to Evidence Mapping
        self.table_map = QTableWidget(0, 3)
        self.table_map.setHorizontalHeaderLabels(["UI Element / Screen", "Associated Findings", "Verified Status"])
        self.table_map.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.table_map.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.view_tabs.addTab(self.table_map, "Component & Screen Evidence")

        right_lay.addWidget(self.view_tabs, 1)
        split.addWidget(right)

        split.setSizes([450, 670])
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
        self.extracted_root = None
        self.screenshots_dir = None
        self.asset_tree.clear()
        self.lbl_asset_name.setText("No asset selected")
        self.badge_status.setText("")
        self.lbl_img_preview.setText("No project loaded")
        self.lbl_img_preview.setPixmap(QPixmap())
        self.txt_preview.setPlainText("")
        self.table_map.setRowCount(0)
        self.stats_lbl.setText("")

    # ---- Loading & Cataloging ------------------------------------------------
    def _load_project(self, pid: int):
        self._clear_all()
        self.current_pid = pid
        p = self.ctx.db.project(pid)
        if not p or not p.get("workdir"):
            return

        workdir = Path(p["workdir"])
        self.extracted_root = workdir / "extracted"
        self.screenshots_dir = workdir / "screenshots"
        self.screenshots_dir.mkdir(parents=True, exist_ok=True)

        # Catalog assets
        all_files = []
        if self.extracted_root.is_dir():
            all_files.extend(list(self.extracted_root.rglob("*")))
        screenshots = list(self.screenshots_dir.glob("*"))

        # Category roots
        root_screens = QTreeWidgetItem(self.asset_tree, ["Screens & Layouts", "", ""])
        root_images = QTreeWidgetItem(self.asset_tree, ["Images & Graphics", "", ""])
        root_styles = QTreeWidgetItem(self.asset_tree, ["Styles & Assets", "", ""])
        root_shots = QTreeWidgetItem(self.asset_tree, ["Reference Screenshots", "", ""])

        count_layouts = 0
        count_images = 0
        count_styles = 0

        for f in all_files:
            if not f.is_file():
                continue
            ext = f.suffix.lower()
            rel = f.relative_to(self.extracted_root).as_posix()
            sz = f"{f.stat().st_size:,} bytes"

            if ext in LAYOUT_EXTS:
                count_layouts += 1
                item = QTreeWidgetItem(root_screens, [rel, ext[1:].upper(), sz])
                item.setData(0, Qt.UserRole, str(f))
            elif ext in IMAGE_EXTS:
                count_images += 1
                item = QTreeWidgetItem(root_images, [rel, ext[1:].upper(), sz])
                item.setData(0, Qt.UserRole, str(f))
            elif ext in STYLE_EXTS:
                count_styles += 1
                item = QTreeWidgetItem(root_styles, [rel, ext[1:].upper(), sz])
                item.setData(0, Qt.UserRole, str(f))

        for s in screenshots:
            if s.is_file() and s.suffix.lower() in IMAGE_EXTS:
                item = QTreeWidgetItem(root_shots, [s.name, "Screenshot", f"{s.stat().st_size:,} bytes"])
                item.setData(0, Qt.UserRole, str(s))

        self.stats_lbl.setText(f"{count_layouts} layouts · {count_images} images · {count_styles} styles · {len(screenshots)} screenshots")
        self.asset_tree.expandAll()

        # Populate screen mapping from findings
        rows = self.ctx.db.findings(pid)
        self._populate_screen_mapping(rows)

    def _populate_screen_mapping(self, rows: list[dict]):
        self.table_map.setRowCount(0)
        items = []

        # Find Android activities
        for r in rows:
            if r["key"] == "android_manifest" and isinstance(r["value"], dict):
                comps = r["value"].get("components", {})
                for act in comps.get("activities", []):
                    act_name = act.get("name", "")
                    exp = "Exported" if act.get("exported") else "Internal"
                    items.append((f"Android Activity: {act_name}", f"Status: {exp}", "VERIFIED MANIFEST"))

            if r["key"] == "decoded_manifest_xml" and isinstance(r["value"], dict):
                xml = r["value"].get("xml", "")
                if "activity" in xml:
                    items.append(("Apktool Screen Hierarchy", "Decoded activities present in AndroidManifest.xml", "VERIFIED RESOURCE"))

            if r["key"] == "package_json" and isinstance(r["value"], dict):
                main_js = r["value"].get("main", "index.js")
                items.append((f"Electron Main Window: {main_js}", "Entrypoint UI module from package.json", "VERIFIED SPEC"))

            if r["key"] == "dotnet_metadata" and isinstance(r["value"], dict):
                for t in r["value"].get("types", []):
                    name = t.get("name", "")
                    if "Form" in name or "Window" in name or "View" in name:
                        items.append((f".NET UI Form/Window: {name}", f"Namespace: {t.get('namespace', '')}", "INFERRED UI STRUCTURE"))

        self.table_map.setRowCount(len(items))
        for row, (c0, c1, c2) in enumerate(items):
            self.table_map.setItem(row, 0, QTableWidgetItem(c0))
            self.table_map.setItem(row, 1, QTableWidgetItem(c1))
            self.table_map.setItem(row, 2, QTableWidgetItem(c2))

    # ---- Asset Selection -----------------------------------------------------
    def _on_asset_selected(self, cur: QTreeWidgetItem, _prev):
        if not cur:
            return
        path_str = cur.data(0, Qt.UserRole)
        if not path_str:
            return

        p = Path(path_str)
        if not p.is_file():
            return

        self.current_selected_path = p
        self.lbl_asset_name.setText(p.name)
        is_screenshot = self.screenshots_dir and self.screenshots_dir in p.parents
        self.badge_status.setText("USER REFERENCE SCREENSHOT" if is_screenshot else "VERIFIED EXTRACTED RESOURCE")

        ext = p.suffix.lower()
        if ext in IMAGE_EXTS:
            self.view_tabs.setCurrentIndex(0)
            pixmap = QPixmap(str(p))
            if not pixmap.isNull():
                # Scale nicely while keeping aspect ratio
                scaled = pixmap.scaled(600, 500, Qt.KeepAspectRatio, Qt.SmoothTransformation)
                self.lbl_img_preview.setPixmap(scaled)
                reader = QImageReader(str(p))
                sz = reader.size()
                self.lbl_asset_name.setText(f"{p.name} ({sz.width()}x{sz.height()} px, {p.stat().st_size:,} bytes)")
            else:
                self.lbl_img_preview.setText(f"Unable to render image: {p.name}")
        elif ext in LAYOUT_EXTS | STYLE_EXTS:
            self.view_tabs.setCurrentIndex(1)
            lang = "xml" if ext in (".xml", ".xaml", ".ui", ".storyboard") else ("html" if ext in (".html", ".htm") else "generic")
            self.highlighter.set_language(lang)
            try:
                content = p.read_text(errors="replace")[:100_000]
                self.txt_preview.setPlainText(content)
            except Exception as e:
                self.txt_preview.setPlainText(f"Error reading file: {e}")
        else:
            self.view_tabs.setCurrentIndex(1)
            self.txt_preview.setPlainText(f"Binary file ({p.stat().st_size:,} bytes)")

    # ---- Actions -------------------------------------------------------------
    def _import_screenshot(self):
        if not self.screenshots_dir:
            QMessageBox.information(self, "Import", "Please select a valid project first.")
            return

        f, _ = QFileDialog.getOpenFileName(self, "Import Reference Screenshot", "", "Images (*.png *.jpg *.jpeg *.webp *.bmp)")
        if f:
            src = Path(f)
            dest = self.screenshots_dir / src.name
            shutil.copyfile(src, dest)
            self.ctx.status(f"Imported screenshot: {src.name}")
            self._load_project(self.current_pid)

    def _export_assets(self):
        if not self.extracted_root or not self.extracted_root.is_dir():
            QMessageBox.information(self, "Export", "No extracted UI assets available for this project.")
            return

        dest_dir = QFileDialog.getExistingDirectory(self, "Export UI Assets To Directory")
        if dest_dir:
            out = Path(dest_dir) / f"reforge_ui_p{self.current_pid:05d}"
            shutil.copytree(self.extracted_root, out, dirs_exist_ok=True)
            if self.screenshots_dir and self.screenshots_dir.is_dir():
                shutil.copytree(self.screenshots_dir, out / "reference_screenshots", dirs_exist_ok=True)
            self.ctx.status(f"Exported UI assets to: {out}")
            QMessageBox.information(self, "Export Complete", f"UI assets exported to:\n{out}")

    def _apply_filter(self, q: str):
        q = q.strip().lower()

        def filter_item(item: QTreeWidgetItem) -> bool:
            child_matches = False
            for i in range(item.childCount()):
                if filter_item(item.child(i)):
                    child_matches = True

            match = q in item.text(0).lower() or q in item.text(1).lower() or child_matches
            item.setHidden(not match and bool(q))
            return match

        for i in range(self.asset_tree.topLevelItemCount()):
            filter_item(self.asset_tree.topLevelItem(i))

    def _export_selected_asset(self):
        if not hasattr(self, "current_selected_path") or not self.current_selected_path or not self.current_selected_path.is_file():
            QMessageBox.information(self, "Export Asset", "Please select an asset from the tree first.")
            return

        save_path, _ = QFileDialog.getSaveFileName(
            self, "Export Asset", self.current_selected_path.name
        )
        if save_path:
            shutil.copy2(self.current_selected_path, save_path)
            self.ctx.status(f"Exported asset to {save_path}")
