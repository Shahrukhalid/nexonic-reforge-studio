"""Technology fingerprinting from byte markers and package layout.

Marker hits are reported as `strongly_inferred` / `tentative`; only structural
evidence (e.g. a .NET CLR header, an APK manifest) is `confirmed` elsewhere.
"""
from __future__ import annotations

from pathlib import Path

from ..core.findings import Confidence, Finding, Provenance

STAGE = "fingerprint"
TOOL = "reforge.fingerprint"
SCAN_BYTES = 64 * 1024 * 1024

# (technology, category, marker bytes, confidence)
BYTE_MARKERS: list[tuple[str, str, bytes, Confidence]] = [
    ("PyInstaller", "packager", b"MEI\x0c\x0b\x0a\x0b\x0e", Confidence.STRONG),
    ("Python runtime", "language", b"Py_Initialize", Confidence.TENTATIVE),
    ("Nuitka", "packager", b"__nuitka", Confidence.STRONG),
    ("Go", "language", b"\xff Go buildinf:", Confidence.STRONG),
    ("Go", "language", b"runtime.gopanic", Confidence.TENTATIVE),
    ("Rust", "language", b"/rustc/", Confidence.STRONG),
    ("Electron", "framework", b"Electron Framework", Confidence.STRONG),
    ("Electron", "framework", b"electron.asar", Confidence.STRONG),
    ("Chromium Embedded Framework", "framework", b"libcef", Confidence.TENTATIVE),
    ("Flutter", "framework", b"Flutter.framework", Confidence.STRONG),
    ("Flutter", "framework", b"libflutter.so", Confidence.STRONG),
    ("Unity", "engine", b"UnityPlayer", Confidence.STRONG),
    ("Unity IL2CPP", "engine", b"il2cpp", Confidence.TENTATIVE),
    ("Unreal Engine", "engine", b"UnrealEngine", Confidence.TENTATIVE),
    ("Qt", "framework", b"QtCore", Confidence.STRONG),
    ("wxWidgets", "framework", b"wxWidgets", Confidence.TENTATIVE),
    ("GTK", "framework", b"libgtk-", Confidence.TENTATIVE),
    ("Swift", "language", b"libswiftCore", Confidence.STRONG),
    ("Objective-C", "language", b"libobjc.A.dylib", Confidence.STRONG),
    ("Delphi / C++Builder", "language", b"Embarcadero", Confidence.TENTATIVE),
    ("Delphi / C++Builder", "language", b"Borland", Confidence.TENTATIVE),
    ("Java (JNI / embedded JVM)", "language", b"JNI_CreateJavaVM", Confidence.TENTATIVE),
    (".NET runtime host", "language", b"hostfxr", Confidence.TENTATIVE),
    ("Mono", "language", b"mono_jit_init", Confidence.STRONG),
    ("GCC", "compiler", b"GCC: (", Confidence.STRONG),
    ("Clang/LLVM", "compiler", b"clang version", Confidence.STRONG),
    ("MinGW", "compiler", b"Mingw-w64 runtime", Confidence.STRONG),
    ("UPX", "packer", b"UPX!", Confidence.STRONG),
    ("Tauri", "framework", b"tauri", Confidence.TENTATIVE),
    ("React Native", "framework", b"ReactNative", Confidence.TENTATIVE),
]

# (technology, category, predicate over relative lower-case file names)
LAYOUT_RULES = [
    ("Electron", "framework", lambda n: n.endswith("resources/app.asar") or n.endswith("/app.asar")),
    ("Electron", "framework", lambda n: "electron framework.framework" in n),
    ("Flutter", "framework", lambda n: n.endswith("libflutter.so") or "flutter.framework" in n
     or n.endswith("flutter_assets/kernel_blob.bin")),
    ("Flutter (AOT Dart)", "framework", lambda n: n.endswith("libapp.so") or "app.framework/app" in n),
    ("Unity", "engine", lambda n: n.endswith("unityplayer.dll") or n.endswith("libunity.so")
     or "unityframework.framework" in n or n.endswith("globalgamemanagers")),
    ("Unity IL2CPP", "engine", lambda n: n.endswith("global-metadata.dat") or n.endswith("gameassembly.dll")
     or n.endswith("libil2cpp.so")),
    ("Unity Mono", "engine", lambda n: n.endswith("managed/assembly-csharp.dll")),
    ("Unreal Engine", "engine", lambda n: n.endswith(".pak") and "content/paks" in n),
    ("Godot", "engine", lambda n: n.endswith(".pck")),
    ("React Native (Hermes)", "framework", lambda n: n.endswith("index.android.bundle") or n.endswith("main.jsbundle")),
    ("Xamarin / .NET MAUI", "framework", lambda n: "assemblies/" in n and n.endswith(".dll")),
    ("Kotlin", "language", lambda n: n.startswith("kotlin/") or n.endswith(".kotlin_module")),
    ("Python (bundled)", "language", lambda n: n.endswith(".pyc") or "/python3" in n and n.endswith(".zip")),
    ("Java", "language", lambda n: n.endswith(".class") or n.endswith(".jar")),
    ("WebAssembly", "language", lambda n: n.endswith(".wasm")),
    ("Sparkle updater", "updater", lambda n: "sparkle.framework" in n),
    ("Squirrel updater", "updater", lambda n: n.endswith("update.exe") or "squirrel" in n),
    ("Native libraries (JNI)", "language", lambda n: n.startswith("lib/") and n.endswith(".so")),
]


def scan_bytes(path: Path, limit: int = SCAN_BYTES) -> list[Finding]:
    rel = path.name
    hits: dict[tuple[str, str], tuple[Confidence, list[str]]] = {}
    overlap = max(len(m) for _, _, m, _ in BYTE_MARKERS)
    prev = b""
    read = 0
    with open(path, "rb") as f:
        while read < limit and (chunk := f.read(min(4 << 20, limit - read))):
            buf = prev + chunk
            for tech, cat, marker, conf in BYTE_MARKERS:
                if marker in buf:
                    k = (tech, cat)
                    old = hits.get(k)
                    best = conf if not old or _rank(conf) > _rank(old[0]) else old[0]
                    ev = (old[1] if old else []) + [repr(marker)[2:-1]]
                    hits[k] = (best, sorted(set(ev)))
            prev = chunk[-overlap:]
            read += len(chunk)
    return [Finding(STAGE, TOOL, "technology", tech, {"category": cat}, conf, Provenance.INFERRED,
                    "byte markers: " + ", ".join(ev), rel) for (tech, cat), (conf, ev) in hits.items()]


def scan_layout(names: list[str], subject: str) -> list[Finding]:
    hits: dict[tuple[str, str], list[str]] = {}
    for n in names:
        ln = n.lower().replace("\\", "/")
        for tech, cat, pred in LAYOUT_RULES:
            if pred(ln):
                lst = hits.setdefault((tech, cat), [])
                if len(lst) < 5:
                    lst.append(n)
    return [Finding(STAGE, TOOL, "technology", tech, {"category": cat}, Confidence.STRONG, Provenance.INFERRED,
                    "files: " + ", ".join(ev), subject) for (tech, cat), ev in hits.items()]


def _rank(c: Confidence) -> int:
    return {Confidence.UNKNOWN: 0, Confidence.TENTATIVE: 1, Confidence.STRONG: 2, Confidence.CONFIRMED: 3}[c]
