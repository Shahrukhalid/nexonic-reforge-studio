"""Milestone 4: Android, PyInstaller, .NET, MSI - all against real, tool-built samples."""
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

from reforge.analysis import android, dotnet, msi, pyinstaller
from reforge.analysis.orchestrator import Orchestrator
from reforge.core.safety import Limits

FIX = Path(__file__).parent / "fixtures"


# ---------------------------------------------------------------- Android
def test_axml_manifest_decoding():
    data = zipfile.ZipFile(FIX / "demo.apk").read("AndroidManifest.xml")
    s = android.manifest_summary(android.parse_axml(data))
    assert s["package"] == "com.nexonic.demo" and s["versionCode"] == 42 and s["versionName"] == "1.4.2"
    assert s["sdk"] == {"minSdkVersion": 24, "targetSdkVersion": 34}
    assert s["permissions"] == ["android.permission.INTERNET", "android.permission.CAMERA"]
    comps = {c["name"]: c for c in s["components"]}
    assert comps[".MainActivity"]["exported"] is True and comps[".SyncService"]["exported"] is False
    assert {c["type"] for c in s["components"]} == {"activity", "service", "receiver", "provider"}
    notes = android.risk_notes(s)
    assert "application is debuggable" in notes and any("CAMERA" in n for n in notes)
    assert not any("allowBackup" in n for n in notes)         # explicitly false in the fixture


def test_manifest_xml_render_uses_android_booleans():
    data = zipfile.ZipFile(FIX / "demo.apk").read("AndroidManifest.xml")
    xml = android.to_xml(android.parse_axml(data))
    assert 'android:debuggable="true"' in xml and 'android:exported="false"' in xml and "True" not in xml


def test_axml_rejects_garbage():
    with pytest.raises(android.AxmlError):
        android.parse_axml(b"\x03\x00\x08\x00" + b"\xff" * 64)


def test_dex_parsing():
    d = android.parse_dex(zipfile.ZipFile(FIX / "demo.apk").read("classes.dex"))
    assert d["class_names"] == ["com.nexonic.demo.MainActivity"] and d["methods"] >= 3


def test_apk_end_to_end(db):
    pid = db.create_project("apk", str(FIX / "demo.apk"), "standard")
    Orchestrator(db).analyze(pid)
    keys = {r["key"]: r["value"] for r in db.findings(pid)}
    assert keys["android_manifest"]["package"] == "com.nexonic.demo"
    assert keys["dex_classes"]["items"] == ["com.nexonic.demo.MainActivity"]
    assert "https://api.nexonic.example/v2/sync" in keys["urls"]


# ---------------------------------------------------------------- MSI
def test_msi_tables_match_msiinfo():
    db = msi.MsiDatabase(FIX / "demo.msi")
    try:
        props = {r["Property"]: r["Value"] for r in db.table("Property")}
        assert props["ProductName"] == "Nexonic Demo Tool" and props["ProductVersion"] == "1.2.3"
        assert props["UpgradeCode"] == "{8F2C1D4E-1B2A-4C3D-9E8F-112233445566}"
        assert db.table("File") == [{"File": "Readme", "Component_": "MainFile", "FileName": "readme.txt",
                                     "FileSize": 24, "Version": None, "Language": None, "Attributes": 512,
                                     "Sequence": 1}]
        reg = db.table("Registry")[0]
        assert reg["Key"] == "Software\\NexonicDemo" and reg["Value"] == "#1" and reg["Root"] == 1
    finally:
        db.close()
    if shutil.which("msiinfo"):        # cross-check with msitools where available
        out = subprocess.run(["msiinfo", "export", str(FIX / "demo.msi"), "File"], capture_output=True, text=True)
        assert "readme.txt\t24" in out.stdout


def test_msi_end_to_end(db):
    pid = db.create_project("msi", str(FIX / "demo.msi"), "standard")
    Orchestrator(db).analyze(pid)
    keys = {r["key"]: r["value"] for r in db.findings(pid)}
    assert keys["msi_product"]["Manufacturer"] == "Nexonic Technologies Test"
    assert keys["msi_summary"]["comments"] == "ReForge test fixture"


# ---------------------------------------------------------------- PyInstaller
@pytest.fixture(scope="module")
def pyi_binary(tmp_path_factory):
    if not shutil.which("pyinstaller"):
        pytest.skip("pyinstaller not installed")
    d = tmp_path_factory.mktemp("pyi")
    (d / "hello_tool.py").write_text('API = "https://license.nexonic.example/api/v1/check"\nprint(API)\n')
    r = subprocess.run(["pyinstaller", "--onefile", "--noconfirm", "--log-level", "ERROR", "--distpath",
                        str(d / "dist"), "--workpath", str(d / "build"), "--specpath", str(d), str(d / "hello_tool.py")],
                       capture_output=True, text=True, timeout=600)
    exe = next((d / "dist").glob("hello_tool*"), None)
    if r.returncode != 0 or exe is None:
        pytest.skip("pyinstaller build failed: " + r.stderr[-300:])
    return exe


def test_pyinstaller_archive(pyi_binary, tmp_path):
    import importlib.util
    a = pyinstaller.find_archive(pyi_binary)
    assert a is not None and a.py_version == f"{sys.version_info.major}.{sys.version_info.minor}"
    assert "hello_tool" in [e.name for e in a.entries if e.typ == "s"]
    files = pyinstaller.extract(a, tmp_path, Limits())
    pyc = (tmp_path / "hello_tool.pyc").read_bytes()
    assert "hello_tool.pyc" in files and pyc[:4] == importlib.util.MAGIC_NUMBER
    assert b"license.nexonic.example" in pyc


def test_pyinstaller_end_to_end(db, pyi_binary):
    pid = db.create_project("pyi", str(pyi_binary), "standard")
    Orchestrator(db).analyze(pid)
    keys = {r["key"]: r["value"] for r in db.findings(pid)}
    assert keys["entry_scripts"]["user"] == ["hello_tool"]
    subjects = [s["path"] for s in keys.get("analysable_subjects", [])] + \
               [r["subject"] for r in db.findings(pid, stage="strings")]
    assert any(s.endswith("::hello_tool.pyc") for s in subjects)


# ---------------------------------------------------------------- .NET
@pytest.fixture(scope="module")
def dotnet_dll(tmp_path_factory):
    d = tmp_path_factory.mktemp("net")
    r = subprocess.run([sys.executable, "-m", "pip", "download", "--no-deps", "-q", "-d", str(d), "pythonnet==3.2.1"],
                       capture_output=True, timeout=180)
    whl = next(d.glob("pythonnet-*.whl"), None)
    if r.returncode != 0 or whl is None:
        pytest.skip("could not download pythonnet wheel (offline?)")
    with zipfile.ZipFile(whl) as z:
        z.extract("pythonnet/runtime/Python.Runtime.dll", d)
    return d / "pythonnet/runtime/Python.Runtime.dll"


def test_dotnet_metadata(dotnet_dll):
    assert dotnet.is_dotnet(dotnet_dll)
    fs = {f.key: f.value for f in dotnet.analyze(dotnet_dll)}
    assert fs["dotnet_assembly"]["assembly"] == "Python.Runtime" and fs["dotnet_assembly"]["version"] == "3.2.1.0"
    assert any(r["name"] == "netstandard" for r in fs["assembly_references"])
    assert fs["dotnet_types"]["count"] > 100
    assert any(p["function"] == "dlopen" for p in fs["pinvoke_imports"])


def test_native_pe_is_not_dotnet(samples):
    assert not dotnet.is_dotnet(samples["native"])
