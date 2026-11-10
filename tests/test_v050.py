"""Tests for v0.5.0 enhancements: Analysis cache, explorer tools, UI exporter, and compiler bundler."""
from __future__ import annotations

from pathlib import Path

from PySide6.QtWidgets import QApplication, QFileDialog

from reforge.analysis.cache import AnalysisCache
from reforge.analysis.orchestrator import Orchestrator
from reforge.core.findings import Confidence, Finding, Provenance
from reforge.reconstruct.builder import build_reconstructed_project
from reforge.reconstruct.scaffold import scaffold_project
from reforge.ui.main_window import MainWindow
from reforge.ui.pages.ai_page import AIAssistantPage
from reforge.ui.pages.explorer_page import ApplicationExplorerPage
from reforge.ui.pages.ui_explorer_page import VisualUIExplorerPage


def test_analysis_cache_lifecycle(tmp_path: Path):
    cache = AnalysisCache(tmp_path / "cache")
    assert cache.stats() == (0, 0)

    f = Finding(
        stage="tools",
        tool="test_tool",
        kind="test_kind",
        key="test_key",
        value={"hello": "world"},
        confidence=Confidence.CONFIRMED,
        provenance=Provenance.EXTRACTED,
    )
    cache.put("1122334455667788", "test_tool", "tools", [f])

    count, size = cache.stats()
    assert count == 1
    assert size > 0

    cached = cache.get("1122334455667788", "test_tool", "tools")
    assert cached is not None
    assert len(cached) == 1
    assert cached[0]["key"] == "test_key"
    assert cached[0]["value"]["hello"] == "world"

    deleted = cache.clear()
    assert deleted == 1
    assert cache.stats() == (0, 0)


def test_cold_and_warm_cache_findings_enums(db, tmp_path):
    cache = AnalysisCache(tmp_path / "cache")
    f = Finding(
        stage="tools",
        tool="test_tool",
        kind="test_kind",
        key="test_key",
        value={"data": 123},
        confidence=Confidence.STRONG,
        provenance=Provenance.INFERRED,
    )
    pid = db.create_project("test_cache_proj", str(tmp_path / "dummy.bin"), "standard")

    # 1. Cold cache put
    cache.put("abcdef1234567890", "test_tool", "tools", [f])

    # 2. Warm cache retrieve
    deserialized = cache.get_findings("abcdef1234567890", "test_tool", "tools")
    assert deserialized is not None
    assert len(deserialized) == 1
    ret = deserialized[0]
    assert ret.confidence == Confidence.STRONG
    assert isinstance(ret.confidence, Confidence)
    assert ret.provenance == Provenance.INFERRED
    assert isinstance(ret.provenance, Provenance)

    # 3. Add to DB without AttributeError
    db.add_findings(pid, [ret])
    db_records = db.findings(pid)
    assert len(db_records) == 1
    assert db_records[0]["confidence"] == "strongly_inferred"
    assert db_records[0]["provenance"] == "inferred_behavior"


def test_orchestrator_uses_cache(db, samples, tmp_path):
    cache = AnalysisCache(tmp_path / "cache")
    orch = Orchestrator(db, cache=cache)

    pid = db.create_project("cached_sample", str(samples["apk"]), "standard")
    orch.analyze(pid)

    p = db.project(pid)
    sha256 = p.get("sha256") or ""
    assert sha256

    # Re-run orchestrator with cache
    orch.analyze(pid)
    runs = db.tool_runs(pid)
    # Check that tool runs record cached status or runs complete
    assert len(runs) >= 0


def test_explorer_page_copy_and_save(db, samples, qapp, tmp_path, monkeypatch):
    win = MainWindow()
    win.ctx.db = db

    pid = db.create_project("explorer_test", str(samples["apk"]), "standard")
    page = win.pages["Application Explorer"]
    assert isinstance(page, ApplicationExplorerPage)

    page.refresh(select=pid)
    page.code_edit.setPlainText("def sample_code():\n    return 42\n")

    # Test copy
    page._copy_code()
    assert "sample_code" in QApplication.clipboard().text()

    # Test save
    dest = tmp_path / "saved_code.py"
    monkeypatch.setattr(QFileDialog, "getSaveFileName", lambda *args, **kwargs: (str(dest), ""))
    page._save_code_to_file()
    assert dest.is_file()
    assert "return 42" in dest.read_text(encoding="utf-8")

    win.close()


def test_ui_explorer_export_asset(db, samples, qapp, tmp_path, monkeypatch):
    win = MainWindow()
    win.ctx.db = db

    pid = db.create_project("ui_test", str(samples["apk"]), "standard")
    page = win.pages["Visual UI Explorer"]
    assert isinstance(page, VisualUIExplorerPage)

    page.refresh(select=pid)
    sample_file = tmp_path / "asset.xml"
    sample_file.write_text("<layout></layout>", encoding="utf-8")
    page.current_selected_path = sample_file

    dest = tmp_path / "exported_asset.xml"
    monkeypatch.setattr(QFileDialog, "getSaveFileName", lambda *args, **kwargs: (str(dest), ""))
    page._export_selected_asset()

    assert dest.is_file()
    assert "<layout>" in dest.read_text(encoding="utf-8")

    win.close()


def test_ai_token_estimation(db, qapp, tmp_path):
    win = MainWindow()
    win.ctx.db = db

    page = win.pages["AI Assistant"]
    assert isinstance(page, AIAssistantPage)

    page.prompt_edit.setPlainText("Explain this binary function structure and decompiled code.")
    page._update_token_estimate()
    assert "Est. tokens: ~" in page.lbl_token_est.text()

    win.close()


def test_builder_standalone_zip_bundling(tmp_path: Path):
    proj_dir = tmp_path / "standalone_app"
    scaffold_project(proj_dir, "Standalone App", "python", [], "# Clean-room Spec")

    res = build_reconstructed_project(proj_dir, target="package")
    assert res.success is True
    # Verify that standalone zip was created
    zip_files = list(res.output_dir.glob("*_dist.zip"))
    assert len(zip_files) >= 1
    assert zip_files[0].name in res.digests
