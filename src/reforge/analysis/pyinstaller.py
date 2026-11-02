"""PyInstaller CArchive reader/extractor (static; the target is never run).

Format: a cookie ('MEI\\x0c\\x0b\\x0a\\x0b\\x0e' + lengths + Python version) at the end of the
archive, a table of contents, and zlib-compressed entries. Entry-point scripts ('s') are
marshalled code objects without a .pyc header; they are written as .pyc using the PYZ
archive's magic so external decompilers (pycdc) can read them. Nothing is unmarshalled here.
"""
from __future__ import annotations

import struct
import zlib
from dataclasses import dataclass
from pathlib import Path

from ..core.findings import Confidence, Finding, Provenance
from ..core.safety import Limits, UnsafeInput, safe_member_path

STAGE = "pyinstaller"
TOOL = "reforge.pyinstaller"
MAGIC = b"MEI\x0c\x0b\x0a\x0b\x0e"
COOKIE = struct.Struct("!8sIIii64s")       # PyInstaller >= 2.1
ENTRY = struct.Struct("!IIIIBc")
TYPES = {"s": "script", "m": "module", "M": "package", "z": "pyz", "Z": "zipfile", "b": "binary", "x": "data",
         "d": "dependency", "o": "runtime option", "n": "symlink", "l": "splash"}
BOOT_PREFIXES = ("pyiboot", "pyi_rth_", "pyimod", "struct", "pyi_")
MAX_SCAN = 1024**3


@dataclass
class TocEntry:
    name: str
    typ: str
    pos: int
    clen: int
    ulen: int
    compressed: bool


@dataclass
class Archive:
    path: Path
    pkg_start: int
    py_version: str
    pylib: str
    entries: list[TocEntry]


def find_archive(path: Path) -> Archive | None:
    size = path.stat().st_size
    with open(path, "rb") as f:
        data = f.read(min(size, MAX_SCAN))
    pos = data.rfind(MAGIC)
    if pos < 0 or pos + COOKIE.size > len(data):
        return None
    _m, len_pkg, toc_off, toc_len, pyver, pylib = COOKIE.unpack_from(data, pos)
    pkg_start = pos + COOKIE.size - len_pkg
    if pkg_start < 0 or toc_off + toc_len > len_pkg:
        raise UnsafeInput("PyInstaller cookie inconsistent")
    entries, p, end = [], pkg_start + toc_off, pkg_start + toc_off + toc_len
    while p + ENTRY.size <= end and len(entries) < 100_000:
        esize, dpos, clen, ulen, flag, typ = ENTRY.unpack_from(data, p)
        if esize < ENTRY.size or p + esize > end:
            raise UnsafeInput("bad TOC entry")
        name = data[p + ENTRY.size:p + esize].rstrip(b"\0").decode("utf-8", "replace")
        entries.append(TocEntry(name, typ.decode(errors="replace"), dpos, clen, ulen, bool(flag)))
        p += esize
    ver = f"{pyver // 100}.{pyver % 100}" if pyver >= 100 else str(pyver)
    return Archive(path, pkg_start, ver, pylib.rstrip(b"\0").decode(errors="replace"), entries)


def read_entry(a: Archive, e: TocEntry, limits: Limits) -> bytes:
    if e.ulen > limits.max_file_bytes or e.clen > limits.max_file_bytes:
        raise UnsafeInput(f"entry too large: {e.name}")
    with open(a.path, "rb") as f:
        f.seek(a.pkg_start + e.pos)
        raw = f.read(e.clen)
    if not e.compressed:
        return raw
    d = zlib.decompressobj()
    out = d.decompress(raw, e.ulen + 1)
    if len(out) > e.ulen:
        raise UnsafeInput(f"entry larger than declared: {e.name}")
    return out


def _pyc_magic(a: Archive, limits: Limits) -> bytes | None:
    for e in a.entries:
        if e.typ == "z":
            head = read_entry(a, e, limits)[:8]
            if head[:4] == b"PYZ\0":
                return head[4:8]
    return None


def is_user_script(name: str) -> bool:
    return not name.startswith(BOOT_PREFIXES)


def extract(a: Archive, dest: Path, limits: Limits) -> list[str]:
    magic = _pyc_magic(a, limits)
    written, total = [], 0
    for e in a.entries[:limits.max_files]:
        if e.typ in ("o", "n"):
            continue
        rel = e.name + (".pyc" if e.typ == "s" else "")
        target = safe_member_path(dest, rel)
        data = read_entry(a, e, limits)
        total += len(data)
        if total > limits.max_total_bytes:
            raise UnsafeInput("PyInstaller extraction size limit exceeded")
        if e.typ == "s" and magic:
            data = magic + b"\0" * 12 + data        # PEP 552 header: magic, flags, 8 bytes padding
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        written.append(rel)
    return written


def findings(a: Archive, rel: str) -> list[Finding]:
    by_type: dict[str, int] = {}
    for e in a.entries:
        by_type[TYPES.get(e.typ, e.typ)] = by_type.get(TYPES.get(e.typ, e.typ), 0) + 1
    scripts = [e.name for e in a.entries if e.typ == "s"]
    user = [s for s in scripts if is_user_script(s)]
    return [
        Finding(STAGE, TOOL, "packager", "pyinstaller_archive",
                {"python": a.py_version, "python_library": a.pylib, "entries": len(a.entries), "by_type": by_type},
                Confidence.CONFIRMED, Provenance.PARSED, "CArchive cookie + TOC", rel),
        Finding(STAGE, TOOL, "entrypoints", "entry_scripts", {"user": user, "bootstrap": [s for s in scripts if s not in user]},
                Confidence.CONFIRMED, Provenance.PARSED, "TOC entries of type 's' (run at startup)", rel),
        Finding(STAGE, TOOL, "dependencies", "bundled_binaries",
                sorted(e.name for e in a.entries if e.typ in ("b", "d"))[:400], subject=rel),
    ]
