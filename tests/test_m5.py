"""Milestone 5 tests: reverse engineering tool ecosystem, adapters, versioning, toolpacks."""
import sys
from pathlib import Path

from reforge.tools import registry, toolpacks
from reforge.tools.adapters import ADAPTERS, apktool, assetripper, binwalk
from reforge.tools.adapters.angr_adapter import is_available, run_angr


def test_registry_85_entries_all_verified():
    reg = registry.load()
    assert len(reg) == 85
    for e in reg:
        assert e["verification"] == "verified", f"{e['name']} not verified"
        assert e["license"], f"{e['name']} missing license"


def test_version_detection_python():
    v = registry._bin_version("python", sys.executable)
    assert v is not None
    assert f"{sys.version_info.major}.{sys.version_info.minor}" in v


def test_binwalk_parse_output():
    sample_output = """
DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             ELF, 64-bit LSB executable, AMD x86-64, version 1 (SYSV)
1048576       0x100000        gzip compressed data, maximum compression, from Unix
"""
    parsed = binwalk.parse_binwalk_output(sample_output)
    assert len(parsed) == 2
    assert parsed[0]["offset_dec"] == 0
    assert parsed[0]["offset_hex"] == "0x0"
    assert "ELF" in parsed[0]["description"]
    assert parsed[1]["offset_dec"] == 1048576
    assert "gzip" in parsed[1]["description"]


def test_binwalk_adapter_mock(tmp_path, monkeypatch):
    target = tmp_path / "firmware.bin"
    target.write_bytes(b"\x7fELF" + b"\x00" * 100)

    class FakeResult:
        ok = True
        returncode = 0
        stdout = "0  0x0  ELF binary header\n"
        stderr = ""

    monkeypatch.setattr(binwalk, "run_tool", lambda argv, timeout: FakeResult())
    status, findings, res = binwalk.run_binwalk("binwalk", target, "firmware.bin", 60)
    assert status == "ok"
    assert len(findings) == 1
    assert findings[0].value["count"] == 1
    assert findings[0].value["signatures"][0]["description"] == "ELF binary header"


def test_apktool_adapter_mock(tmp_path, monkeypatch):
    target = tmp_path / "app.apk"
    target.write_bytes(b"PK\x03\x04fakeapk")

    def fake_run_tool(argv, timeout):
        out_dir = Path(argv[argv.index("-o") + 1])
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "AndroidManifest.xml").write_text('<manifest package="com.demo"/>')
        res_dir = out_dir / "res" / "values"
        res_dir.mkdir(parents=True, exist_ok=True)
        (res_dir / "strings.xml").write_text("<resources/>")

        class Res:
            ok = True
            returncode = 0
            stdout = ""
            stderr = ""
        return Res()

    monkeypatch.setattr(apktool, "run_tool", fake_run_tool)
    status, findings, _ = apktool.run_apktool("apktool", target, "app.apk", 60)
    assert status == "ok"
    assert any(f.key == "apktool_decoded" for f in findings)
    assert any(f.key == "decoded_manifest_xml" for f in findings)


def test_assetripper_adapter_mock(tmp_path, monkeypatch):
    target = tmp_path / "data.unity3d"
    target.write_bytes(b"UnityWeb fake")

    def fake_run_tool(argv, timeout):
        out_dir = Path(argv[argv.index("-o") + 1])
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "texture.png").write_bytes(b"PNG")

        class Res:
            ok = True
            returncode = 0
            stdout = ""
            stderr = ""
        return Res()

    monkeypatch.setattr(assetripper, "run_tool", fake_run_tool)
    status, findings, _ = assetripper.run_assetripper("AssetRipper", target, "data.unity3d", 60)
    assert status == "ok"
    assert len(findings) == 1
    assert findings[0].value["count"] == 1


def test_angr_adapter_fallback(tmp_path):
    target = tmp_path / "dummy.bin"
    target.write_bytes(b"not an elf")
    if not is_available():
        status, findings = run_angr(target, "dummy.bin")
        assert status == "skipped" and findings == []
    else:
        status, findings = run_angr(target, "dummy.bin")
        assert status in ("ok", "error")


def test_toolpacks_multi_platform_resolve():
    p = toolpacks.packs()
    assert "ghidra" in p
    assert "jadx" in p
    assert "wabt" in p

    wabt_spec = p["wabt"]
    resolved = toolpacks.resolve_spec(wabt_spec)
    assert "url" in resolved
    assert "sha256" in resolved
    assert resolved["url"].startswith("https://github.com/WebAssembly/wabt/releases/download/")
    assert len(resolved["sha256"]) == 64


def test_adapters_list_contains_m5_tools():
    tool_names = {a.tool for a in ADAPTERS}
    assert "Apktool" in tool_names
    assert "Binwalk" in tool_names
    assert "AssetRipper" in tool_names
    assert "JADX" in tool_names
    assert "Ghidra" in tool_names
