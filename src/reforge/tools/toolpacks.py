"""Verified tool-pack installer.

Each pack is pinned to one release URL + SHA-256 (packs.json). Downloads go to
a temp file, are hash-checked *before* extraction, and are extracted with the
same safety limits used for untrusted input. Nothing downloaded is executed
during installation.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import ssl
import tempfile
import urllib.request
from collections.abc import Callable
from functools import lru_cache
from pathlib import Path

from ..analysis.extract import extract_zip
from ..core import paths
from ..core.safety import Limits, UnsafeInput

PACKS_FILE = Path(__file__).with_name("packs.json")
PACK_LIMITS = Limits(max_files=150_000, max_total_bytes=6 * 1024**3, max_file_bytes=1024**3, max_ratio=400)


class ChecksumMismatch(Exception):
    pass


@lru_cache(maxsize=1)
def packs() -> dict:
    return json.loads(PACKS_FILE.read_text())


def tools_dir() -> Path:
    p = paths.data_dir() / "tools"
    p.mkdir(parents=True, exist_ok=True)
    return p


def install_dir(pack_id: str) -> Path:
    return tools_dir() / pack_id


def is_installed(pack_id: str) -> bool:
    return (install_dir(pack_id) / ".reforge-pack.json").is_file()


def bin_dirs() -> list[str]:
    """Executable directories of installed packs (searched by registry.find_exe)."""
    out = []
    for pid, spec in packs().items():
        if is_installed(pid):
            out += [str(install_dir(pid) / d) for d in spec.get("bin_dirs", [])]
    if os.environ.get("GHIDRA_INSTALL_DIR"):
        out.append(str(Path(os.environ["GHIDRA_INSTALL_DIR"]) / "support"))
    return out


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while b := f.read(1 << 20):
            h.update(b)
    return h.hexdigest()


def _tls() -> ssl.SSLContext:
    """Verified TLS using certifi's CA bundle (works even when the OS Python has no CA store)."""
    try:
        import certifi
        return ssl.create_default_context(cafile=certifi.where())
    except ImportError:
        return ssl.create_default_context()


def download(url: str, dest: Path, progress: Callable[[int, int], None] | None = None) -> None:
    if not url.startswith(("https://", "file://")):
        raise UnsafeInput("tool packs must be downloaded over HTTPS")
    with urllib.request.urlopen(url, timeout=60, context=_tls()) as r, open(dest, "wb") as f:  # noqa: S310
        total = int(r.headers.get("Content-Length") or 0)
        done = 0
        while chunk := r.read(1 << 20):
            f.write(chunk)
            done += len(chunk)
            if progress:
                progress(done, total)


def install(pack_id: str, progress: Callable[[int, int], None] | None = None, spec: dict | None = None) -> Path:
    spec = spec or packs()[pack_id]
    dest = install_dir(pack_id)
    with tempfile.TemporaryDirectory(dir=tools_dir()) as tmp:
        archive = Path(tmp) / "download.bin"
        download(spec["url"], archive, progress)
        got = sha256_file(archive)
        if got != spec["sha256"].lower():
            raise ChecksumMismatch(f"{pack_id}: expected {spec['sha256']}, got {got}")
        staging = Path(tmp) / "staging"
        staging.mkdir()
        if spec.get("format", "zip") != "zip":
            raise ValueError(f"unsupported pack format: {spec.get('format')}")
        extract_zip(archive, staging, PACK_LIMITS, preserve_exec=True)
        (staging / ".reforge-pack.json").write_text(json.dumps(
            {"id": pack_id, "version": spec["version"], "sha256": got, "url": spec["url"]}, indent=1))
        if dest.exists():
            shutil.rmtree(dest)
        shutil.move(str(staging), dest)
    return dest


def uninstall(pack_id: str) -> None:
    d = install_dir(pack_id)
    if d.is_dir() and tools_dir() in d.parents:
        shutil.rmtree(d)
