"""Milestone 3: Capstone disassembly, tool packs, Ghidra/DIE adapters, UI fixes."""
import hashlib
import shutil
import zipfile

import pytest

from reforge.analysis import disasm
from reforge.analysis.orchestrator import Orchestrator
from reforge.tools import registry, toolpacks
from reforge.tools.adapters import ghidra


def test_disasm_native(samples):
    fs = disasm.analyze(samples["native"])
    entry = [f for f in fs if f.key.endswith("entrypoint")]
    assert entry, [f.key for f in fs]
    v = entry[0].value
    assert v["arch"] in {"x86-64", "x86", "arm64", "arm"} and len(v["lines"]) > 3


def test_disasm_macho_arm64(samples):
    if "macho" not in samples:
        pytest.skip("no Mach-O object")
    fs = disasm.analyze(samples["macho"])
    exp = [f for f in fs if "export:" in f.key]
    assert exp and exp[0].value["arch"] == "arm64"
    assert any(" add " in ln or ln.endswith("ret") or " ret" in ln for ln in exp[0].value["lines"])


def test_orchestrator_records_disasm(db, samples):
    pid = db.create_project("n", str(samples["native"]), "standard")
    Orchestrator(db).analyze(pid)
    assert db.findings(pid, stage="disasm")
    assert any(r["tool"] == "capstone" and r["status"] == "ok" for r in db.tool_runs(pid))


def _make_pack(tmp_path):
    z = tmp_path / "pack.zip"
    with zipfile.ZipFile(z, "w") as zf:
        info = zipfile.ZipInfo("demo_1.0/support/hello")
        info.external_attr = 0o755 << 16
        zf.writestr(info, "#!/bin/sh\necho hi\n")
        zf.writestr("demo_1.0/README", "x")
    sha = hashlib.sha256(z.read_bytes()).hexdigest()
    return {"name": "Demo", "version": "1.0", "license": "MIT", "url": z.as_uri(), "sha256": sha,
            "format": "zip", "platforms": ["linux", "macos", "windows"], "bin_dirs": ["demo_1.0/support"]}


def test_toolpack_install_verifies_checksum(tmp_path, monkeypatch):
    spec = _make_pack(tmp_path)
    monkeypatch.setattr(toolpacks, "packs", lambda: {"demo": spec})
    dest = toolpacks.install("demo")
    assert (dest / "demo_1.0/support/hello").is_file()
    assert toolpacks.is_installed("demo")
    assert str(dest / "demo_1.0/support") in toolpacks.bin_dirs()
    import os
    if os.name != "nt":
        assert os.access(dest / "demo_1.0/support/hello", os.X_OK)
    toolpacks.uninstall("demo")
    assert not toolpacks.is_installed("demo")


def test_toolpack_rejects_bad_checksum(tmp_path, monkeypatch):
    spec = _make_pack(tmp_path) | {"sha256": "0" * 64}
    monkeypatch.setattr(toolpacks, "packs", lambda: {"demo": spec})
    with pytest.raises(toolpacks.ChecksumMismatch):
        toolpacks.install("demo")
    assert not toolpacks.is_installed("demo")


def test_toolpack_rejects_plain_http(tmp_path):
    with pytest.raises(Exception, match="HTTPS"):
        toolpacks.download("http://example.com/x.zip", tmp_path / "x")


def test_ghidra_pack_pinned():
    spec = toolpacks.packs()["ghidra"]
    assert spec["url"].startswith("https://github.com/NationalSecurityAgency/ghidra/releases/download/")
    assert len(spec["sha256"]) == 64


def test_ghidra_parse_export():
    data = {"program": "a.out", "language": "x86:LE:64:default", "compiler": "gcc", "image_base": "00100000",
            "function_count": 3, "functions": [
                {"name": "main", "entry": "00101000", "size": 40, "thunk": False, "external": False,
                 "signature": "int main(void)", "calls": ["puts"], "decompiled": "int main(void){puts(\"x\");}"},
                {"name": "puts", "entry": "EXTERNAL:0", "size": 1, "thunk": False, "external": True,
                 "signature": "int puts(char *)", "calls": []}]}
    fs = {f.key: f for f in ghidra.parse_export(data, "a.out")}
    assert fs["functions"].value["internal"] == 1
    assert fs["call_graph"].value["items"] == [["main", "puts"]]
    assert fs["main"].provenance.value == "decompiled"


@pytest.mark.skipif(not registry.find_exe("Ghidra"), reason="Ghidra not installed")
def test_ghidra_integration(db, samples):
    if not registry.find_exe("Ghidra"):   # re-check under the per-test REFORGE_HOME
        pytest.skip("Ghidra not reachable (set GHIDRA_INSTALL_DIR)")
    target = samples.get("elf") or samples["native"]
    pid = db.create_project("g", str(target), "deep")
    Orchestrator(db).analyze(pid)
    rows = [r for r in db.findings(pid, stage="tools") if r["tool"] == "ghidra"]
    funcs = next(r for r in rows if r["key"] == "functions")
    assert funcs["value"]["internal"] > 10
    assert any(r["kind"] == "decompiled" for r in rows)


@pytest.mark.skipif(not shutil.which("diec"), reason="Detect It Easy not installed")
def test_die_integration(db, samples):
    pid = db.create_project("d", str(samples["native"]), "quick")
    Orchestrator(db).analyze(pid)
    r = next(x for x in db.findings(pid, stage="tools") if x["tool"] == "diec")
    assert r["kind"] == "tool_output" and "detects" in str(r["value"]).lower()


def test_tool_table_numeric_sort(qtbot):
    from PySide6.QtCore import Qt

    from reforge.ui.main_window import MainWindow
    w = MainWindow()
    qtbot.addWidget(w)
    t = w.pages["Tool Manager"]
    t.refresh()
    t.table.sortItems(0, Qt.AscendingOrder)
    ids = [int(t.table.item(r, 0).text()) for r in range(t.table.rowCount())]
    assert ids == sorted(ids) and ids[0] == 1 and ids[-1] == 85
    w.close()
