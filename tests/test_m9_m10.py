"""Tests for Milestone 9-10: Clean-room project export, SBOM manifests, reports, and packaging pipeline."""
from __future__ import annotations

import json
import tarfile
import zipfile
from pathlib import Path

from PySide6.QtWidgets import QMessageBox

from reforge.core.findings import Finding
from reforge.export.exporter import (
    export_cleanroom_archive,
    export_report_bundle,
    export_sbom,
    sha256_file,
)
from reforge.ui.main_window import MainWindow
from reforge.ui.pages.export_page import BuildExportPage


def test_export_cleanroom_archive_zip(tmp_path: Path):
    src_dir = tmp_path / "my_project"
    src_dir.mkdir()
    (src_dir / "src").mkdir()
    (src_dir / "src" / "main.py").write_text("print('hello')\n", encoding="utf-8")
    (src_dir / "README.md").write_text("# Project\n", encoding="utf-8")

    out_zip = tmp_path / "dist" / "my_project.zip"
    archive, digest = export_cleanroom_archive(src_dir, out_zip)

    assert archive.is_file()
    assert digest == sha256_file(archive)

    sha_file = archive.with_suffix(archive.suffix + ".sha256")
    assert sha_file.is_file()
    assert digest in sha_file.read_text(encoding="utf-8")

    with zipfile.ZipFile(archive, "r") as zf:
        names = zf.namelist()
        assert "src/main.py" in names
        assert "README.md" in names


def test_export_cleanroom_archive_targz(tmp_path: Path):
    src_dir = tmp_path / "rs_project"
    src_dir.mkdir()
    (src_dir / "Cargo.toml").write_text('[package]\nname = "test"\n', encoding="utf-8")

    out_tar = tmp_path / "dist" / "rs_project.tar.gz"
    archive, digest = export_cleanroom_archive(src_dir, out_tar)

    assert archive.is_file()
    assert digest == sha256_file(archive)

    with tarfile.open(archive, "r:gz") as tar:
        names = tar.getnames()
        assert "Cargo.toml" in names


def test_export_sbom(db, tmp_path: Path):
    pid = db.create_project(name="demo_app", input_path=str(tmp_path / "demo.exe"))
    db.update_project(pid, sha256="abc12345", size=1024)

    db.add_findings(pid, [
        Finding(stage="structure", tool="lief", kind="libraries", key="libraries", value=["KERNEL32.dll", "USER32.dll", "ADVAPI32.dll"]),
        Finding(stage="unpack", tool="nodejs", kind="manifest", key="package_json", value={"dependencies": {"express": "^4.18.2", "cors": "^2.8.5"}}),
        Finding(stage="structure", tool="dotnet", kind="metadata", key="dotnet_metadata", value={"assembly_refs": [{"name": "System.Runtime", "version": "8.0.0.0"}]}),
    ])

    out_sbom = tmp_path / "sbom.json"
    result = export_sbom(db, pid, out_sbom)

    assert result.is_file()
    data = json.loads(result.read_text(encoding="utf-8"))

    assert data["bomFormat"] == "CycloneDX-Compatible"
    assert data["metadata"]["component"]["name"] == "demo_app"
    assert len(data["components"]) == 6  # 3 libs + 2 npm pkgs + 1 dotnet assembly

    names = {c["name"] for c in data["components"]}
    assert "KERNEL32.dll" in names
    assert "express" in names
    assert "System.Runtime" in names


def test_export_report_bundle(db, tmp_path: Path):
    pid = db.create_project(name="report_test", input_path=str(tmp_path / "sample"))
    db.update_project(pid, sha256="999999", size=2048)
    db.add_findings(pid, [Finding(stage="id", tool="id", kind="format", key="format", value="ELF")])

    bundle_dir = tmp_path / "reports"
    bundle = export_report_bundle(db, pid, bundle_dir)

    assert bundle["markdown"].is_file()
    assert bundle["json"].is_file()
    assert bundle["sbom"].is_file()


def test_build_export_page_gui(db, qapp, tmp_path, monkeypatch):
    win = MainWindow()
    win.ctx.db = db

    pid = db.create_project(name="gui_proj", input_path=str(tmp_path / "gui.bin"))
    db.update_project(pid, sha256="1234", size=500)

    page = win.pages["Build & Export"]
    assert isinstance(page, BuildExportPage)

    page.refresh(select=pid)
    assert page.current_pid == pid
    assert page.proj_sel.count() >= 1

    # Test packaging validation message
    monkeypatch.setattr(QMessageBox, "information", lambda *args, **kwargs: QMessageBox.Ok)
    monkeypatch.setattr(QMessageBox, "critical", lambda *args, **kwargs: QMessageBox.Ok)
    page._validate_packaging_config()

    # Test report export triggered
    monkeypatch.setattr(
        "reforge.ui.pages.export_page.QFileDialog.getExistingDirectory",
        lambda *args, **kwargs: str(tmp_path / "export_dir"),
    )
    page._export_report_bundle()
    assert (tmp_path / "export_dir").is_dir()

    win.close()


def test_packaging_spec_and_installer_files():
    root = Path(__file__).resolve().parents[1]

    # Verify PyInstaller spec
    spec_path = root / "packaging" / "reforge.spec"
    assert spec_path.is_file()
    spec_content = spec_path.read_text(encoding="utf-8")
    assert "reforge.export" in spec_content
    assert "reforge.reconstruct" in spec_content
    assert "reforge.ai" in spec_content
    assert '"0.4.0"' in spec_content

    # Verify Inno Setup installer script
    iss_path = root / "packaging" / "windows" / "installer.iss"
    assert iss_path.is_file()
    iss_content = iss_path.read_text(encoding="utf-8")
    assert '#define AppVer "0.4.0"' in iss_content
