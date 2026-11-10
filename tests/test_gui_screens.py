"""Comprehensive GUI visual verification test: renders every page and captures screenshots."""
from __future__ import annotations

import re
from pathlib import Path

from reforge.analysis.orchestrator import Orchestrator
from reforge.core.findings import Confidence, Finding, Provenance
from reforge.reconstruct.scaffold import scaffold_project
from reforge.ui.main_window import MainWindow


def test_render_and_capture_all_12_pages(db, samples, qapp, tmp_path):
    docs_dir = Path(__file__).resolve().parents[1] / "docs" / "screenshots"
    docs_dir.mkdir(parents=True, exist_ok=True)

    # Create and analyze a project with rich findings
    pid = db.create_project("Comprehensive Verification App", str(samples["apk"]), "standard")
    Orchestrator(db).analyze(pid)

    # Add mock UI and structure findings for visual completeness
    p = db.project(pid)
    wd = Path(p["workdir"])

    # UI assets
    ui_dir = wd / "extracted" / "res" / "layout"
    ui_dir.mkdir(parents=True, exist_ok=True)
    (ui_dir / "activity_main.xml").write_text("<LinearLayout><Button/></LinearLayout>", encoding="utf-8")
    (wd / "extracted" / "styles.css").write_text("body { background: #1e1e1e; color: #fff; }", encoding="utf-8")

    db.add_findings(pid, [
        Finding(
            stage="structure",
            tool="lief",
            kind="libraries",
            key="libraries",
            value=["libc.so", "libm.so", "libssl.so"],
            confidence=Confidence.CONFIRMED,
            provenance=Provenance.PARSED,
        ),
        Finding(
            stage="strings",
            tool="strings",
            kind="urls",
            key="urls",
            value=["https://api.nexonic.com/v1/auth", "https://cdn.nexonic.com/assets"],
            confidence=Confidence.CONFIRMED,
            provenance=Provenance.EXTRACTED,
        ),
    ])

    # Scaffold clean-room project
    recon_dir = wd / "reconstructed" / "nexonic_cleanroom"
    scaffold_project(recon_dir, "Nexonic CleanRoom", "python", ["Auth Client", "Asset Cache"], "# Clean Room Specification")

    win = MainWindow()
    win.ctx.db = db
    win.resize(1280, 800)
    win.show()

    assert len(win.pages) == 12, f"Expected 12 pages, found {len(win.pages)}"

    captured_screens = []
    for idx, (title, _page) in enumerate(win.pages.items()):
        # Switch to page
        win.show_page(title, select=pid)
        qapp.processEvents()

        # Capture screenshot
        slug = re.sub(r"[^a-zA-Z0-9]+", "_", title.lower()).strip("_")
        img_path = docs_dir / f"{idx:02d}_{slug}.png"
        pix = win.grab()
        saved = pix.save(str(img_path), "PNG")
        assert saved, f"Failed to save screenshot for {title}"
        assert img_path.is_file() and img_path.stat().st_size > 5000
        captured_screens.append(img_path)

    win.close()
    assert len(captured_screens) == 12
