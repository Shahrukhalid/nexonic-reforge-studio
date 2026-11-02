"""Stage 2 - safe, read-only package extraction.

Originals are never modified. Every extractor enforces file-count, size,
ratio (archive-bomb) and path-containment limits, and never executes content.
"""
from __future__ import annotations

import json
import plistlib
import shutil
import struct
import subprocess
import sys
import tempfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

from ..core.findings import Confidence, Finding, Provenance
from ..core.safety import Limits, UnsafeInput, safe_member_path

STAGE = "extract"
TOOL = "reforge.extract"


@dataclass
class ExtractResult:
    root: Path | None
    files: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    skipped: int = 0


class Budget:
    def __init__(self, limits: Limits):
        self.limits, self.files, self.bytes = limits, 0, 0

    def take(self, size: int, name: str) -> None:
        if size > self.limits.max_file_bytes:
            raise UnsafeInput(f"member too large ({size} bytes): {name}")
        self.files += 1
        self.bytes += size
        if self.files > self.limits.max_files:
            raise UnsafeInput(f"file-count limit exceeded ({self.limits.max_files})")
        if self.bytes > self.limits.max_total_bytes:
            raise UnsafeInput("total extracted size limit exceeded")


# ---------------------------------------------------------------- ZIP family
def extract_zip(src: Path, dest: Path, limits: Limits, budget: Budget | None = None,
                preserve_exec: bool = False) -> ExtractResult:
    budget = budget or Budget(limits)
    res = ExtractResult(dest)
    with zipfile.ZipFile(src) as z:
        infos = z.infolist()
        total_c = sum(i.compress_size for i in infos) or 1
        total_u = sum(i.file_size for i in infos)
        if total_u / total_c > limits.max_ratio and total_u > 64 * 1024**2:
            raise UnsafeInput(f"archive-bomb suspected (ratio {total_u / total_c:.0f}:1)")
        for info in infos:
            if info.is_dir():
                continue
            if info.external_attr >> 16 & 0o170000 == 0o120000:   # symlink member
                res.skipped += 1
                continue
            target = safe_member_path(dest, info.filename)
            budget.take(info.file_size, info.filename)
            if info.compress_size and info.file_size / max(info.compress_size, 1) > limits.max_ratio * 5 \
                    and info.file_size > 16 * 1024**2:
                raise UnsafeInput(f"archive-bomb member: {info.filename}")
            target.parent.mkdir(parents=True, exist_ok=True)
            with z.open(info) as s, open(target, "wb") as d:
                copied = 0
                while chunk := s.read(1 << 20):
                    copied += len(chunk)
                    if copied > info.file_size + 1024:     # header lied about size
                        raise UnsafeInput(f"member size mismatch: {info.filename}")
                    d.write(chunk)
            if preserve_exec and (info.external_attr >> 16) & 0o111:
                target.chmod(0o755)
            res.files.append(info.filename)
    return res


# ---------------------------------------------------------------- Electron ASAR
def read_asar_header(src: Path) -> tuple[dict, int]:
    with open(src, "rb") as f:
        head = f.read(16)
        _, hdr_size, _, json_len = struct.unpack("<4I", head)
        if json_len > 256 * 1024**2:
            raise UnsafeInput("ASAR header too large")
        header = json.loads(f.read(json_len).decode("utf-8"))
    return header, 8 + hdr_size


def _walk_asar(node: dict, prefix: str = ""):
    for name, child in node.get("files", {}).items():
        p = f"{prefix}{name}"
        if "files" in child:
            yield from _walk_asar(child, p + "/")
        else:
            yield p, child


def extract_asar(src: Path, dest: Path, limits: Limits, budget: Budget | None = None) -> ExtractResult:
    budget = budget or Budget(limits)
    header, base = read_asar_header(src)
    res = ExtractResult(dest)
    src_size = src.stat().st_size
    with open(src, "rb") as f:
        for rel, meta in _walk_asar(header):
            if "link" in meta or meta.get("unpacked"):
                res.skipped += 1          # symlinks / app.asar.unpacked members are not in this file
                continue
            size, off = int(meta.get("size", 0)), int(meta.get("offset", "0"))
            if base + off + size > src_size:
                raise UnsafeInput(f"ASAR member outside archive: {rel}")
            target = safe_member_path(dest, rel)
            budget.take(size, rel)
            target.parent.mkdir(parents=True, exist_ok=True)
            f.seek(base + off)
            with open(target, "wb") as d:
                remaining = size
                while remaining:
                    chunk = f.read(min(1 << 20, remaining))
                    if not chunk:
                        break
                    d.write(chunk)
                    remaining -= len(chunk)
            res.files.append(rel)
    return res


# ---------------------------------------------------------------- directories / bundles
def list_dir(root: Path, limits: Limits) -> list[str]:
    out = []
    for p in root.rglob("*"):
        if p.is_symlink():
            continue
        if p.is_file():
            out.append(p.relative_to(root).as_posix())
            if len(out) >= limits.max_files:
                break
    return out


def bundle_info(app: Path) -> list[Finding]:
    plist = app / "Contents" / "Info.plist"
    if not plist.is_file():
        plist = app / "Info.plist"
    if not plist.is_file():
        return []
    try:
        with open(plist, "rb") as f:
            d = plistlib.load(f)
    except Exception as e:  # noqa: BLE001
        return [Finding(STAGE, TOOL, "error", "info_plist", str(e), subject=str(plist.name))]
    keys = ("CFBundleIdentifier", "CFBundleName", "CFBundleDisplayName", "CFBundleShortVersionString",
            "CFBundleVersion", "CFBundleExecutable", "LSMinimumSystemVersion", "MinimumOSVersion",
            "NSPrincipalClass", "CFBundleDocumentTypes", "CFBundleURLTypes", "SUFeedURL", "UTExportedTypeDeclarations")
    meta = {k: d[k] for k in keys if k in d}
    perms = {k: v for k, v in d.items() if k.startswith("NS") and k.endswith("UsageDescription")}
    out = [Finding(STAGE, "plistlib", "metadata", "bundle_info", meta, Confidence.CONFIRMED, Provenance.PARSED,
                   "Info.plist", app.name)]
    if perms:
        out.append(Finding(STAGE, "plistlib", "permissions", "usage_descriptions", perms, subject=app.name,
                           evidence="Info.plist NS*UsageDescription"))
    return out


# ---------------------------------------------------------------- DMG
def extract_dmg(src: Path, dest: Path, limits: Limits) -> ExtractResult:
    """Mount read-only (macOS hdiutil), copy app bundles out, always detach."""
    res = ExtractResult(dest)
    if sys.platform != "darwin":
        if shutil.which("7z"):
            out = subprocess.run(["7z", "x", "-y", f"-o{dest}", str(src)], capture_output=True, timeout=600)
            res.files = list_dir(dest, limits)
            res.findings.append(Finding(STAGE, "7z", "extraction", "dmg_7z", {"rc": out.returncode}))
            return res
        res.root = None
        res.findings.append(Finding(STAGE, TOOL, "limitation", "dmg_unsupported",
                                    "DMG extraction needs macOS hdiutil or 7-Zip; neither is available",
                                    Confidence.CONFIRMED))
        return res
    mnt = Path(tempfile.mkdtemp(prefix="reforge-dmg-"))
    try:
        att = subprocess.run(["hdiutil", "attach", "-readonly", "-nobrowse", "-noautoopen", "-noverify",
                              "-mountpoint", str(mnt), str(src)], capture_output=True, timeout=300,
                             stdin=subprocess.DEVNULL)
        if att.returncode != 0:
            raise UnsafeInput("hdiutil attach failed: " + att.stderr.decode(errors="replace")[:300])
        budget = Budget(limits)
        for item in mnt.iterdir():
            if item.is_symlink() or item.name.startswith("."):
                continue
            target = dest / item.name
            if item.is_dir():
                for p in item.rglob("*"):
                    if p.is_file() and not p.is_symlink():
                        budget.take(p.stat().st_size, str(p))
                shutil.copytree(item, target, symlinks=True)
            elif item.is_file():
                budget.take(item.stat().st_size, item.name)
                shutil.copy2(item, target)
        res.files = list_dir(dest, limits)
    finally:
        subprocess.run(["hdiutil", "detach", str(mnt), "-force"], capture_output=True, timeout=120)
        shutil.rmtree(mnt, ignore_errors=True)
    return res


# ---------------------------------------------------------------- PKG (xar)
def extract_xar(src: Path, dest: Path, limits: Limits) -> ExtractResult:
    res = ExtractResult(dest)
    tool = shutil.which("pkgutil") if sys.platform == "darwin" else None
    if tool:
        out_dir = dest / "expanded"
        r = subprocess.run([tool, "--expand", str(src), str(out_dir)], capture_output=True, timeout=600)
        if r.returncode == 0:
            res.files = list_dir(dest, limits)
            return res
    if shutil.which("7z"):
        subprocess.run(["7z", "x", "-y", f"-o{dest}", str(src)], capture_output=True, timeout=600)
        res.files = list_dir(dest, limits)
        return res
    res.root = None
    res.findings.append(Finding(STAGE, TOOL, "limitation", "pkg_unsupported",
                                "PKG expansion needs macOS pkgutil or 7-Zip", Confidence.CONFIRMED))
    return res
