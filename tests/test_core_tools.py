"""Milestone 3 completion: Rizin adapter, ImHex launcher, Frida bridge."""
import subprocess
import sys

import pytest

from reforge.tools import external, frida_bridge, registry
from reforge.tools.adapters import ADAPTERS, rizin_argv, run_adapter


def test_rizin_argv(tmp_path):
    t = tmp_path / "a.bin"
    assert rizin_argv("/usr/bin/rz-bin", t) == ["/usr/bin/rz-bin", "-Ij", str(t)]
    assert rizin_argv(r"C:\rizin\bin\rz-bin.exe", t)[1] == "-Ij"
    assert rizin_argv("/usr/bin/rizin", t) == ["/usr/bin/rizin", "-q", "-c", "ij", str(t)]


def test_rizin_integration(samples):
    if not registry.find_exe("Rizin"):
        pytest.skip("Rizin not installed")
    a = next(x for x in ADAPTERS if x.tool == "Rizin")
    status, findings, _ = run_adapter(a, samples["native"], "native")
    assert status == "ok", findings
    v = findings[0].value
    assert isinstance(v, dict) and any(k in v for k in ("core", "bin", "info", "arch", "bintype", "format")), str(v)[:500]


def test_imhex_found_in_app_bundle(tmp_path, monkeypatch):
    fake = tmp_path / "ImHex.app/Contents/MacOS/imhex"
    fake.parent.mkdir(parents=True)
    fake.write_text("")
    monkeypatch.setattr(registry, "host_os", lambda: "macos")
    monkeypatch.setitem(registry.APP_PATHS, "imhex", {"macos": [str(fake)]})
    monkeypatch.setattr(registry.shutil, "which", lambda *a, **k: None)
    assert registry.find_exe("ImHex") == str(fake)


def test_open_in_imhex_uses_copy(tmp_path, monkeypatch):
    src = tmp_path / "input.bin"
    src.write_bytes(b"\x7fELF original")
    seen = {}

    class FakePopen:
        def __init__(self, argv, **kw):
            seen["argv"], seen["kw"] = argv, kw

    monkeypatch.setattr(external, "find_imhex", lambda: "/opt/imhex")
    monkeypatch.setattr(subprocess, "Popen", FakePopen)
    _, copy = external.open_in_imhex(src, tmp_path / "work")
    assert seen["argv"] == ["/opt/imhex", str(copy)] and copy != src
    assert copy.read_bytes() == src.read_bytes()
    assert seen["kw"].get("shell") is False


def test_open_in_imhex_rejects_missing_tool_and_dirs(tmp_path, monkeypatch):
    monkeypatch.setattr(external, "find_imhex", lambda: None)
    with pytest.raises(external.ExternalToolError):
        external.open_in_imhex(tmp_path / "x")
    monkeypatch.setattr(external, "find_imhex", lambda: "/opt/imhex")
    with pytest.raises(external.ExternalToolError):
        external.open_in_imhex(tmp_path)


def test_frida_instrumentation_disabled():
    with pytest.raises(frida_bridge.DynamicAnalysisDisabled):
        frida_bridge.instrument("anything")


def test_frida_integration():
    if not frida_bridge.info():
        pytest.skip("frida not installed")
    devs = frida_bridge.devices()
    assert any(d["type"] == "local" for d in devs), devs
    assert registry.status_of(registry.by_name("Frida")).available


@pytest.mark.skipif(sys.platform != "darwin", reason="ImHex cask check runs on macOS CI")
def test_imhex_integration():
    if not external.find_imhex():
        pytest.skip("ImHex not installed")
    assert registry.status_of(registry.by_name("ImHex")).available
