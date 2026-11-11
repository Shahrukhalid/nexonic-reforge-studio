"""Stage 3a - native executable structure via LIEF (ELF / PE / Mach-O)."""
from __future__ import annotations

from pathlib import Path

import lief

from ..core.findings import Confidence, Finding, Provenance

STAGE = "binary"
TOOL = "lief"
MAX_LIST = 400

lief.logging.disable()


def _enum(v) -> str:
    s = str(v)
    return s.split(".")[-1]


def _sections(b) -> list[dict]:
    out = []
    for s in list(b.sections)[:MAX_LIST]:
        try:
            ent = round(s.entropy, 3)
        except Exception:  # noqa: BLE001
            ent = None
        out.append({"name": s.name, "size": s.size, "vaddr": s.virtual_address, "entropy": ent})
    return out


def _one(b, rel: str, slice_tag: str = "") -> list[Finding]:
    f: list[Finding] = []
    hdr = b.abstract.header
    tag = f"[{slice_tag}] " if slice_tag else ""
    info = {"format": _enum(b.format), "arch": _enum(hdr.architecture), "bits": 64 if hdr.is_64 else 32,
            "endianness": _enum(hdr.endianness), "entrypoint": hex(b.entrypoint), "pie": bool(b.is_pie),
            "nx": bool(b.has_nx)}
    libs = [str(x) for x in b.libraries][:MAX_LIST]
    imports = sorted({fn.name for fn in b.imported_functions if fn.name})
    exports = sorted({fn.name for fn in b.exported_functions if fn.name})

    if isinstance(b, lief.PE.Binary):
        info["subsystem"] = _enum(b.optional_header.subsystem)
        info["machine"] = _enum(b.header.machine)
        info["timestamp"] = b.header.time_date_stamps
        info["signed"] = bool(b.has_signatures)
        info["dotnet"] = _has_clr(b)
        info["rich_header"] = bool(b.has_rich_header)
        if b.has_rich_header:
            info["rich_entries"] = [{"id": e.id, "build": e.build_id, "count": e.count} for e in b.rich_header.entries][:60]
        info["has_resources"] = bool(b.has_resources)
        imp_by_lib = {i.name: [e.name for e in i.entries if e.name][:200] for i in b.imports}
        f.append(Finding(STAGE, TOOL, "imports", tag + "imports_by_library", imp_by_lib, subject=rel))
        if b.has_resources:
            try:
                vi = b.resources_manager.version
                if vi:
                    f.append(Finding(STAGE, TOOL, "metadata", tag + "version_info", _pe_version(vi), subject=rel))
            except Exception:  # noqa: BLE001
                pass
    elif isinstance(b, lief.ELF.Binary):
        info["interpreter"] = b.interpreter if b.has_interpreter else None
        info["type"] = _enum(b.header.file_type)
        info["stripped"] = not any(True for _ in b.symtab_symbols)
    elif isinstance(b, lief.MachO.Binary):
        info["filetype"] = _enum(b.header.file_type)
        info["code_signature"] = bool(b.has_code_signature)
        info["encrypted"] = any(getattr(c, "crypt_id", 0) for c in b.commands
                                if isinstance(c, lief.MachO.EncryptionInfo))
        segs = [s.name for s in b.segments]
        sects = {s.name for s in b.sections}
        info["segments"] = segs
        f.append(Finding(STAGE, TOOL, "language", tag + "objc_metadata", any(s.startswith("__objc") for s in sects),
                         Confidence.CONFIRMED, evidence="__objc_* sections", subject=rel))
        f.append(Finding(STAGE, TOOL, "language", tag + "swift_metadata", any(s.startswith("__swift5") for s in sects),
                         Confidence.CONFIRMED, evidence="__swift5_* sections", subject=rel))
        if b.has_build_version:
            bv = b.build_version
            info["platform"] = _enum(bv.platform)
            info["minos"] = ".".join(map(str, bv.minos))
            info["sdk"] = ".".join(map(str, bv.sdk))

    f.insert(0, Finding(STAGE, TOOL, "binary", tag + "header", info, subject=rel))
    f.append(Finding(STAGE, TOOL, "binary", tag + "sections", _sections(b), subject=rel))
    f.append(Finding(STAGE, TOOL, "dependencies", tag + "libraries", libs, subject=rel))
    f.append(Finding(STAGE, TOOL, "imports", tag + "imported_functions",
                     {"count": len(imports), "items": imports[:MAX_LIST]}, subject=rel))
    f.append(Finding(STAGE, TOOL, "exports", tag + "exported_functions",
                     {"count": len(exports), "items": exports[:MAX_LIST]}, subject=rel))
    syms = sorted({s.name for s in getattr(b, "symbols", []) if getattr(s, "name", None)})
    if syms:
        f.append(Finding(STAGE, TOOL, "function", tag + "recovered_functions",
                         {"count": len(syms), "items": syms[:MAX_LIST]}, subject=rel))
    return f


def _has_clr(b) -> bool:
    try:
        dd = b.data_directory(lief.PE.DataDirectory.TYPES.CLR_RUNTIME_HEADER)
        return dd.rva != 0 and dd.size != 0
    except Exception:  # noqa: BLE001
        return False


def _pe_version(vi) -> dict:
    out: dict = {}
    try:
        for table in vi.string_file_info.children:
            for e in table.entries:
                out[str(e.key)] = str(e.value)
    except Exception:  # noqa: BLE001
        pass
    return out


def analyze(path: Path, rel: str = "") -> list[Finding]:
    rel = rel or Path(path).name
    try:
        fat = lief.MachO.parse(str(path)) if lief.is_macho(str(path)) else None
    except Exception:  # noqa: BLE001
        fat = None
    if fat is not None:
        slices = list(fat)
        if len(slices) == 1:
            return _one(slices[0], rel)
        out = []
        for i, b in enumerate(slices):
            out += _one(b, rel, f"slice{i}:{_enum(b.header.cpu_type)}")
        return out
    b = lief.parse(str(path))
    if b is None:
        return [Finding(STAGE, TOOL, "error", "parse_failed", "LIEF could not parse this file",
                        Confidence.CONFIRMED, Provenance.PARSED, subject=rel)]
    return _one(b, rel)
