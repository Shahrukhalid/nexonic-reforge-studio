"""Stage 1 - content-based file identification (never trusts the extension alone)."""
from __future__ import annotations

import hashlib
import math
import struct
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

from ..core.findings import Confidence, Finding, Provenance

STAGE = "identify"
TOOL = "reforge.identify"


@dataclass
class Identity:
    path: Path
    fmt: str                       # e.g. "elf", "pe", "macho", "macho-fat", "apk", "dmg", ...
    family: str                    # executable | archive | package | bytecode | bundle | data
    description: str
    confidence: Confidence = Confidence.CONFIRMED
    details: dict = field(default_factory=dict)


MACHO_MAGICS = {b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe"}


def file_hashes(path: Path, chunk: int = 1 << 20) -> dict:
    h = {n: hashlib.new(n) for n in ("md5", "sha1", "sha256")}
    with open(path, "rb") as f:
        while b := f.read(chunk):
            for x in h.values():
                x.update(b)
    return {n: x.hexdigest() for n, x in h.items()}


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in counts if c)


def _zip_kind(path: Path) -> tuple[str, str, dict]:
    try:
        with zipfile.ZipFile(path) as z:
            names = z.namelist()
    except (zipfile.BadZipFile, OSError):
        return "zip", "ZIP archive (unreadable central directory)", {}
    s = set(names)
    det = {"entries": len(names)}
    if "AndroidManifest.xml" in s and any(n.endswith(".dex") for n in names):
        return "apk", "Android application package (APK)", det
    if "BundleConfig.pb" in s and any(n.endswith("/manifest/AndroidManifest.xml") for n in names):
        return "aab", "Android App Bundle (AAB)", det
    if any(n.startswith("Payload/") and ".app/" in n for n in names):
        return "ipa", "iOS application archive (IPA)", det
    if any(n.lower().endswith(".nuspec") for n in names):
        return "nupkg", "NuGet package", det
    if "META-INF/MANIFEST.MF" in s or any(n.endswith(".class") for n in names):
        kind = "war" if any(n.startswith("WEB-INF/") for n in names) else "jar"
        return kind, f"Java archive ({kind.upper()})", det
    if "[Content_Types].xml" in s:
        return "ooxml", "Office Open XML document", det
    if any(n.endswith(".whl") or n.endswith(".dist-info/WHEEL") for n in names):
        return "wheel", "Python wheel", det
    return "zip", "ZIP archive", det


def _is_asar(head: bytes) -> bool:
    if len(head) < 16:
        return False
    a, hdr_size, payload, json_len = struct.unpack_from("<4I", head)
    return a == 4 and payload + 4 == hdr_size and 0 < json_len <= payload and head[16:17] == b"{"


def identify(path: Path) -> Identity:
    path = Path(path)
    if path.is_dir():
        if (path / "Contents" / "Info.plist").is_file():
            return Identity(path, "app-bundle", "bundle", "macOS application bundle (.app)")
        if (path / "Info.plist").is_file() and path.suffix == ".app":
            return Identity(path, "ios-app-bundle", "bundle", "iOS application bundle (.app)")
        return Identity(path, "directory", "bundle", "Directory", Confidence.CONFIRMED)

    size = path.stat().st_size
    with open(path, "rb") as f:
        head = f.read(4096)
        tail = b""
        if size >= 512:
            f.seek(size - 512)
            tail = f.read(512)

    m4 = head[:4]
    if head[:4] == b"\x7fELF":
        if head[8:11] == b"AI\x02":
            return Identity(path, "appimage", "package", "AppImage (type 2, ELF runtime)")
        return Identity(path, "elf", "executable", "ELF executable / shared object")
    if head[:2] == b"MZ" and len(head) >= 0x40:
        off = struct.unpack_from("<I", head, 0x3C)[0]
        sig = head[off:off + 4] if off + 4 <= len(head) else _read_at(path, off, 4)
        if sig == b"PE\x00\x00":
            return Identity(path, "pe", "executable", "Windows PE executable / DLL")
        return Identity(path, "mz", "executable", "MS-DOS MZ executable", Confidence.STRONG)
    if m4 in MACHO_MAGICS:
        return Identity(path, "macho", "executable", "Mach-O binary")
    if m4 == b"\xca\xfe\xba\xbe":
        nfat = struct.unpack(">I", head[4:8])[0]
        if 0 < nfat < 40:   # Java class files carry a version number > 40 here
            return Identity(path, "macho-fat", "executable", f"Mach-O universal binary ({nfat} slices)",
                            details={"slices": nfat})
        return Identity(path, "java-class", "bytecode", "Java class file")
    if head[:4] == b"\x00asm":
        ver = struct.unpack("<I", head[4:8])[0] if len(head) >= 8 else None
        return Identity(path, "wasm", "bytecode", "WebAssembly module", details={"version": ver})
    if head[:4] == b"dex\n":
        return Identity(path, "dex", "bytecode", "Dalvik executable (DEX)", details={"version": head[4:7].decode(errors="replace")})
    if head[:8] == bytes.fromhex("c61fbc03c103191f"):
        return Identity(path, "hermes", "bytecode", "Hermes JavaScript bytecode (React Native)")
    if head[:4] == b"PK\x03\x04" or head[:4] == b"PK\x05\x06":
        fmt, desc, det = _zip_kind(path)
        fam = "package" if fmt in {"apk", "aab", "ipa", "nupkg", "jar", "war", "wheel"} else "archive"
        return Identity(path, fmt, fam, desc, details=det)
    if head[:8] == bytes.fromhex("d0cf11e0a1b11ae1"):
        if path.suffix.lower() in {".msi", ".msp", ".msm"}:
            return Identity(path, "msi", "package", "Windows Installer package (OLE compound file)", Confidence.STRONG)
        return Identity(path, "ole", "archive", "OLE compound file")
    if head[:4] == b"xar!":
        return Identity(path, "xar-pkg", "package", "XAR archive (macOS .pkg installer)")
    if tail[:4] == b"koly":
        return Identity(path, "dmg", "package", "Apple disk image (UDIF/DMG)")
    if head[:7] == b"UnityFS" or head[:8] == b"UnityWeb":
        return Identity(path, "unity-bundle", "archive", "Unity asset bundle")
    if _is_asar(head):
        return Identity(path, "asar", "archive", "Electron ASAR archive")
    if len(head) > 16 and head[2:4] == b"\r\n" and path.suffix == ".pyc":
        return Identity(path, "pyc", "bytecode", "Python bytecode (.pyc)", Confidence.STRONG,
                        details={"magic": head[:4].hex()})
    if head[:2] == b"\x1f\x8b":
        return Identity(path, "gzip", "archive", "gzip stream")
    if head[:6] == b"\xfd7zXZ\x00":
        return Identity(path, "xz", "archive", "xz stream")
    if head[:6] == b"7z\xbc\xaf\x27\x1c":
        return Identity(path, "7z", "archive", "7-Zip archive")
    if head[257:262] == b"ustar":
        return Identity(path, "tar", "archive", "tar archive")
    if head[:2] in (b"#!",):
        return Identity(path, "script", "data", "Script with shebang: " + head.split(b"\n", 1)[0][:80].decode(errors="replace"))
    return Identity(path, "unknown", "data", "Unrecognised format", Confidence.UNKNOWN)


def _read_at(path: Path, off: int, n: int) -> bytes:
    with open(path, "rb") as f:
        f.seek(off)
        return f.read(n)


def identify_findings(path: Path, rel: str = "") -> tuple[Identity, list[Finding]]:
    ident = identify(path)
    rel = rel or path.name
    out = [Finding(STAGE, TOOL, "format", "format", {"format": ident.fmt, "family": ident.family,
                   "description": ident.description, **ident.details}, ident.confidence,
                   Provenance.PARSED, "magic bytes / container structure", rel)]
    if path.is_file():
        size = path.stat().st_size
        with open(path, "rb") as f:
            sample = f.read(4 * 1024 * 1024)
        out.append(Finding(STAGE, TOOL, "file", "hashes", {"size": size, **file_hashes(path)}, subject=rel))
        out.append(Finding(STAGE, TOOL, "file", "entropy",
                           {"sample_bytes": len(sample), "shannon": round(entropy(sample), 3)},
                           subject=rel, evidence="first 4 MiB"))
        if path.suffix and ident.fmt not in ("unknown",):
            out.append(Finding(STAGE, TOOL, "file", "extension", path.suffix.lower(), subject=rel))
    return ident, out
