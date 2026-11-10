import json
import os
import shutil
import struct
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

NATIVE_FMT = {"darwin": {"macho", "macho-fat"}, "win32": {"pe"}}.get(sys.platform, {"elf"})

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")


@pytest.fixture(autouse=True)
def reforge_home(tmp_path, monkeypatch):
    monkeypatch.setenv("REFORGE_HOME", str(tmp_path / "home"))
    return tmp_path / "home"


@pytest.fixture(autouse=True)
def flush_qt_events():
    yield
    try:
        from PySide6.QtCore import QCoreApplication
        app = QCoreApplication.instance()
        if app:
            app.sendPostedEvents()
            app.processEvents()
    except Exception:
        pass


@pytest.fixture
def db(reforge_home):
    from reforge.core.db import Database
    d = Database()
    yield d
    d.close()


def make_asar(path: Path, files: dict[str, bytes]) -> Path:
    tree, blobs, off = {"files": {}}, b"", 0
    for name, data in files.items():
        node = tree
        parts = name.split("/")
        for p in parts[:-1]:
            node = node["files"].setdefault(p, {"files": {}})
        node["files"][parts[-1]] = {"size": len(data), "offset": str(off)}
        blobs += data
        off += len(data)
    js = json.dumps(tree).encode()
    pad = (4 - len(js) % 4) % 4
    payload = struct.pack("<I", len(js)) + js + b"\0" * pad
    header = struct.pack("<I", len(payload)) + payload
    path.write_bytes(struct.pack("<II", 4, len(header)) + header + blobs)
    return path


@pytest.fixture
def samples(tmp_path):
    d = tmp_path / "samples"
    d.mkdir()
    s = {}
    s["apk"] = d / "demo.apk"
    with zipfile.ZipFile(s["apk"], "w") as z:
        z.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00fake-axml")
        z.writestr("classes.dex", b"dex\n035\0" + b"\0" * 100 + b"https://api.example.com/v1/users")
        z.writestr("lib/arm64-v8a/libflutter.so", b"\x7fELF" + b"\0" * 60)
    s["jar"] = d / "demo.jar"
    with zipfile.ZipFile(s["jar"], "w") as z:
        z.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\nMain-Class: demo.Main\n")
        z.writestr("demo/Main.class", b"\xca\xfe\xba\xbe\x00\x00\x00\x41")
    s["wasm"] = d / "m.wasm"
    s["wasm"].write_bytes(b"\x00asm\x01\x00\x00\x00")
    s["asar"] = make_asar(d / "app.asar", {"package.json": b'{"name":"demo","main":"main.js","version":"1.2.3"}',
                                           "main.js": b"fetch('https://telemetry.example.org/api/v2/ping')",
                                           "src/ui/index.html": b"<html></html>"})
    s["slip"] = d / "slip.zip"
    with zipfile.ZipFile(s["slip"], "w") as z:
        z.writestr("../../evil.txt", b"x")
    s["bomb"] = d / "bomb.zip"
    with zipfile.ZipFile(s["bomb"], "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("zeros.bin", b"\0" * (80 * 1024 * 1024))
    # host-native executable: ELF on Linux, Mach-O (often universal) on macOS, PE on Windows
    s["native"] = Path(sys.executable).resolve()
    if sys.platform.startswith("linux"):
        s["elf"] = Path(shutil.which("ls") or "/bin/ls").resolve()
    clang = shutil.which("clang")
    if clang:
        c = d / "t.c"
        c.write_text("int add(int a,int b){return a+b;}\n")
        o = d / "t_macho.o"
        if subprocess.run([clang, "-target", "arm64-apple-macos13", "-c", str(c), "-o", str(o)],
                          capture_output=True).returncode == 0:
            s["macho"] = o
    return s
