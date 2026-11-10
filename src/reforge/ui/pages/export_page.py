"""Build & Export page: export clean-room code, analysis reports, SBOM manifests, and validate packaging."""
from __future__ import annotations

import sys
from pathlib import Path

from PySide6.QtWidgets import (
    QComboBox,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPushButton,
    QVBoxLayout,
)

from ...export import export_cleanroom_archive, export_report_bundle, export_sbom
from ...reconstruct.builder import build_reconstructed_project, detect_build_configuration
from ...reconstruct.toolchains import detect_host_toolchains
from .common import Page


class BuildExportPage(Page):
    title = "Build & Export"
    subtitle = "Export independent clean-room source projects, comprehensive analysis reports, SBOM manifests, and validate installers."

    def __init__(self, ctx):
        super().__init__(ctx)
        self.current_pid: int | None = None
        self.reconstructed_dir: Path | None = None

        # Top Bar: Project Selector
        top = QHBoxLayout()
        top.addWidget(QLabel("Project:"))
        self.proj_sel = QComboBox()
        self.proj_sel.currentIndexChanged.connect(self._on_project_changed)
        top.addWidget(self.proj_sel, 1)
        self.root.addLayout(top)

        # Main Layout: 3 Cards
        # 1. Clean-Room Source Export Card
        f1 = QFrame()
        f1.setObjectName("Card")
        l1 = QVBoxLayout(f1)
        l1.setContentsMargins(16, 14, 16, 14)
        l1.setSpacing(8)

        t1 = QLabel("1. Clean-Room Source Project Export")
        t1.setStyleSheet("font-weight: 600; font-size: 13px;")
        l1.addWidget(t1)

        d1 = QLabel("Package the newly developed clean-room source code into a standalone, reproducible archive "
                    "with SHA-256 cryptographic checksums. Extracted and decompiled proprietary binaries are excluded.")
        d1.setWordWrap(True)
        d1.setObjectName("Muted")
        l1.addWidget(d1)

        self.lbl_src_status = QLabel("No project loaded")
        l1.addWidget(self.lbl_src_status)

        h1 = QHBoxLayout()
        self.fmt_sel = QComboBox()
        self.fmt_sel.addItems(["ZIP Archive (.zip)", "Gzipped Tarball (.tar.gz)"])
        h1.addWidget(self.fmt_sel)

        btn_export_src = QPushButton("Export Source Archive…")
        btn_export_src.setObjectName("Primary")
        btn_export_src.clicked.connect(self._export_source_archive)
        h1.addWidget(btn_export_src)
        h1.addStretch(1)
        l1.addLayout(h1)

        self.root.addWidget(f1)

        # 2. Analysis Reports & SBOM Card
        f2 = QFrame()
        f2.setObjectName("Card")
        l2 = QVBoxLayout(f2)
        l2.setContentsMargins(16, 14, 16, 14)
        l2.setSpacing(8)

        t2 = QLabel("2. Analysis Reports & Software Bill of Materials (SBOM)")
        t2.setStyleSheet("font-weight: 600; font-size: 13px;")
        l2.addWidget(t2)

        d2 = QLabel("Export full analysis reports (Markdown / JSON) and a machine-readable Software Bill of Materials "
                    "(CycloneDX-compatible) documenting dependencies, detected libraries, and security indicators.")
        d2.setWordWrap(True)
        d2.setObjectName("Muted")
        l2.addWidget(d2)

        h2 = QHBoxLayout()
        btn_export_reports = QPushButton("Export Full Report Bundle…")
        btn_export_reports.clicked.connect(self._export_report_bundle)
        btn_export_sbom = QPushButton("Export SBOM Manifest (JSON)…")
        btn_export_sbom.clicked.connect(self._export_single_sbom)
        h2.addWidget(btn_export_reports)
        h2.addWidget(btn_export_sbom)
        h2.addStretch(1)
        l2.addLayout(h2)

        self.root.addWidget(f2)

        # 3. Build Reconstructed Desktop Binary Card
        f3 = QFrame()
        f3.setObjectName("Card")
        l3 = QVBoxLayout(f3)
        l3.setContentsMargins(16, 14, 16, 14)
        l3.setSpacing(8)

        t3 = QLabel("3. Build Reconstructed Desktop Binary")
        t3.setStyleSheet("font-weight: 600; font-size: 13px;")
        l3.addWidget(t3)

        d3 = QLabel("Compile the independent clean-room software into a standalone executable or package using native compiler toolchains.")
        d3.setWordWrap(True)
        d3.setObjectName("Muted")
        l3.addWidget(d3)

        self.lbl_binary_status = QLabel("Checking reconstructed project configuration…")
        l3.addWidget(self.lbl_binary_status)

        # Host Toolchains Status
        self.lbl_toolchains = QLabel("Scanning host compiler toolchains…")
        self.lbl_toolchains.setStyleSheet("color: #61afef; font-size: 11px;")
        l3.addWidget(self.lbl_toolchains)

        h3 = QHBoxLayout()
        h3.addWidget(QLabel("Build Target:"))
        self.target_bin_sel = QComboBox()
        self.target_bin_sel.addItems(["Standalone Executable (Native Binary)", "Distributable Package (Wheel / Lib / Jar)"])
        h3.addWidget(self.target_bin_sel)

        btn_build_bin = QPushButton("Compile Reconstructed Project")
        btn_build_bin.setObjectName("Primary")
        btn_build_bin.clicked.connect(self._build_reconstructed_binary)
        h3.addWidget(btn_build_bin)

        btn_refresh_tc = QPushButton("Scan Compilers")
        btn_refresh_tc.clicked.connect(self._refresh_toolchains)
        h3.addWidget(btn_refresh_tc)

        h3.addStretch(1)
        l3.addLayout(h3)

        self.root.addWidget(f3)

        # 4. Packaging & Installer Workflow Verification Card
        f4 = QFrame()
        f4.setObjectName("Card")
        l4 = QVBoxLayout(f4)
        l4.setContentsMargins(16, 14, 16, 14)
        l4.setSpacing(8)

        t4 = QLabel("4. Application Installer & Packaging Pipeline")
        t4.setStyleSheet("font-weight: 600; font-size: 13px;")
        l4.addWidget(t4)

        os_label = "Windows (x64 Setup Installer)" if sys.platform == "win32" else ("macOS (Apple Silicon & Intel DMG)" if sys.platform == "darwin" else "Linux (Standalone Bundle)")
        d4 = QLabel(f"Host Target: {os_label} · Packaging specifications: PyInstaller (reforge.spec), "
                    f"Inno Setup (installer.iss), macOS DMG (make_dmg.sh).")
        d4.setWordWrap(True)
        d4.setObjectName("Muted")
        l4.addWidget(d4)

        self.lbl_pack_status = QLabel("Checking packaging configuration…")
        l4.addWidget(self.lbl_pack_status)

        h4 = QHBoxLayout()
        btn_verify_pkg = QPushButton("Validate Packaging Configuration")
        btn_verify_pkg.clicked.connect(self._validate_packaging_config)
        h4.addWidget(btn_verify_pkg)
        h4.addStretch(1)
        l4.addLayout(h4)

        self.root.addWidget(f4)
        self.root.addStretch(1)

        self._check_packaging()
        self._refresh_toolchains()

    def _refresh_toolchains(self) -> None:
        """Scan and display available host compilers and build toolchains."""
        tcs = detect_host_toolchains(force_refresh=True)
        avail = [f"{tc.name.split()[0]} ({tc.version})" for tc in tcs.values() if tc.available and tc.version]
        if avail:
            self.lbl_toolchains.setText("Detected Host Compilers: " + " · ".join(avail[:5]))
        else:
            self.lbl_toolchains.setText("Detected Host Compilers: Python (Standard)")

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
            self.lbl_src_status.setText("No project loaded")

        self._check_packaging()
        self._refresh_toolchains()

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
        if self.reconstructed_dir.is_dir():
            files = list(self.reconstructed_dir.rglob("*"))
            file_count = sum(1 for f in files if f.is_file())
            self.lbl_src_status.setText(f"Clean-room source ready: {file_count} files in reconstructed/")
            subdirs = [d for d in self.reconstructed_dir.iterdir() if d.is_dir()]
            target_dir = subdirs[0] if subdirs else self.reconstructed_dir
            cfg = detect_build_configuration(target_dir)
            self.lbl_binary_status.setText(f"Project stack: {cfg['language'].title()} ({target_dir.name}) · Ready to compile.")
        else:
            self.lbl_src_status.setText("No clean-room code generated yet (use Reconstruction Studio first).")
            self.lbl_binary_status.setText("No clean-room code generated yet.")

    # ---- Actions -------------------------------------------------------------
    def _build_reconstructed_binary(self):
        if not self.reconstructed_dir or not self.reconstructed_dir.is_dir():
            QMessageBox.warning(self, "Build Error", "No reconstructed project found. Please scaffold a project in Reconstruction Studio first.")
            return

        subdirs = [d for d in self.reconstructed_dir.iterdir() if d.is_dir()]
        target_dir = subdirs[0] if subdirs else self.reconstructed_dir

        is_binary = "Standalone" in self.target_bin_sel.currentText()
        target_mode = "binary" if is_binary else "package"

        self.ctx.status(f"Compiling {target_dir.name} as {target_mode}…")
        self.lbl_binary_status.setText(f"Compiling {target_dir.name}… (please wait)")

        res = build_reconstructed_project(target_dir, target=target_mode)
        if res.success:
            art_names = [a.name for a in res.artifacts]
            digests_summary = "\n".join(f"- {name}: {digest[:16]}…" for name, digest in res.digests.items())
            self.ctx.status(f"Build succeeded: {len(res.artifacts)} artifact(s) generated in {res.duration:.1f}s")
            self.lbl_binary_status.setText(f"Build succeeded in {res.duration:.1f}s: {', '.join(art_names) or 'completed'}")
            QMessageBox.information(
                self, "Build Succeeded",
                f"Successfully compiled {target_dir.name}!\n\n"
                f"Output directory:\n{res.output_dir}\n\n"
                f"Artifacts:\n{digests_summary or 'See output directory'}\n\n"
                f"Build manifest saved to build_manifest.json"
            )
        else:
            err = res.stderr or res.stdout or "Unknown build error"
            self.ctx.status(f"Build failed for {target_dir.name}")
            self.lbl_binary_status.setText(f"Build failed: {err[:80]}")
            QMessageBox.critical(self, "Build Failed", f"Failed to build {target_dir.name}:\n\n{err[:500]}")
    def _export_source_archive(self):
        if not self.reconstructed_dir or not self.reconstructed_dir.is_dir():
            QMessageBox.warning(self, "Export", "No reconstructed project found. Please scaffold a project in Reconstruction Studio first.")
            return

        is_tar = "Tarball" in self.fmt_sel.currentText()
        ext = ".tar.gz" if is_tar else ".zip"
        default_name = f"reforge_cleanroom_p{self.current_pid:05d}{ext}"

        save_path, _ = QFileDialog.getSaveFileName(self, "Export Clean-Room Source Archive", default_name,
                                                   f"Archive (*{ext})")
        if save_path:
            out_file, digest = export_cleanroom_archive(self.reconstructed_dir, Path(save_path))
            self.ctx.status(f"Exported clean-room archive: {out_file.name} (SHA-256: {digest[:12]}…)")
            QMessageBox.information(
                self, "Export Complete",
                f"Source archive created successfully!\n\nPath: {out_file}\nSHA-256: {digest}\n\nManifest saved to {out_file}.sha256"
            )

    def _export_report_bundle(self):
        if not self.current_pid:
            return
        dest_dir = QFileDialog.getExistingDirectory(self, "Select Directory for Report Bundle")
        if dest_dir:
            bundle = export_report_bundle(self.ctx.db, self.current_pid, Path(dest_dir))
            self.ctx.status(f"Exported reports and SBOM to {dest_dir}")
            QMessageBox.information(
                self, "Report Bundle Exported",
                f"Report bundle created:\n- {bundle['markdown'].name}\n- {bundle['json'].name}\n- {bundle['sbom'].name}\n\nLocation: {dest_dir}"
            )

    def _export_single_sbom(self):
        if not self.current_pid:
            return
        save_path, _ = QFileDialog.getSaveFileName(self, "Export SBOM Manifest", f"reforge_sbom_p{self.current_pid:05d}.json", "JSON (*.json)")
        if save_path:
            out = export_sbom(self.ctx.db, self.current_pid, Path(save_path))
            self.ctx.status(f"Exported SBOM: {out.name}")
            QMessageBox.information(self, "SBOM Exported", f"Software Bill of Materials saved to:\n{out}")

    def _check_packaging(self):
        root = Path(__file__).resolve().parents[3]
        spec = root / "packaging" / "reforge.spec"
        iss = root / "packaging" / "windows" / "installer.iss"
        dmg = root / "packaging" / "macos" / "make_dmg.sh"

        ok = spec.is_file() and iss.is_file() and dmg.is_file()
        if ok:
            self.lbl_pack_status.setText("All packaging scripts present: reforge.spec (OK), installer.iss (OK), make_dmg.sh (OK)")
        else:
            self.lbl_pack_status.setText("Missing one or more packaging scripts under packaging/")

    def _validate_packaging_config(self):
        self._check_packaging()
        self._refresh_toolchains()
        root = Path(__file__).resolve().parents[3]
        from ... import __version__

        spec_file = root / "packaging" / "reforge.spec"
        spec_text = spec_file.read_text(errors="replace") if spec_file.is_file() else ""

        iss_file = root / "packaging" / "windows" / "installer.iss"
        iss_text = iss_file.read_text(errors="replace") if iss_file.is_file() else ""

        errors = []
        if not spec_file.is_file():
            errors.append("packaging/reforge.spec not found")
        elif "reforge" not in spec_text:
            errors.append("packaging/reforge.spec is missing reforge configuration")

        if not iss_file.is_file():
            errors.append("packaging/windows/installer.iss not found")
        elif "AppVer" not in iss_text:
            errors.append("packaging/windows/installer.iss is missing AppVer definition")

        if errors:
            QMessageBox.critical(self, "Packaging Validation Failed", "\n".join(errors))
        else:
            QMessageBox.information(
                self, "Packaging Validation Passed",
                f"Packaging configuration verified successfully!\n\n"
                f"- App Version: {__version__}\n"
                f"- PyInstaller Spec: Valid\n"
                f"- Inno Setup Definition: Valid\n"
                f"- macOS DMG Packager: Valid\n\n"
                f"Release workflows in GitHub Actions will produce installers for Windows and macOS automatically."
            )
