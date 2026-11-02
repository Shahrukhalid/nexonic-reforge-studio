"""Entry-point and exported-function disassembly with Capstone (static; nothing is executed)."""
from __future__ import annotations

from pathlib import Path

import capstone as cs
import lief

from ..core.findings import Confidence, Finding, Provenance

STAGE = "disasm"
TOOL = "capstone"
MAX_INSNS = 120
WINDOW = 1024
MAX_EXPORTS = 8

lief.logging.disable()


def _engine(b) -> tuple[cs.Cs, str] | None:
    arch = str(b.abstract.header.architecture).split(".")[-1]
    is64 = b.abstract.header.is_64
    if arch in ("X86_64", "I386", "X86"):
        mode = cs.CS_MODE_64 if is64 or arch == "X86_64" else cs.CS_MODE_32
        return cs.Cs(cs.CS_ARCH_X86, mode), "x86-64" if mode == cs.CS_MODE_64 else "x86"
    if arch in ("ARM64", "AARCH64"):
        return cs.Cs(cs.CS_ARCH_ARM64, cs.CS_MODE_ARM), "arm64"
    if arch == "ARM":
        return cs.Cs(cs.CS_ARCH_ARM, cs.CS_MODE_ARM), "arm"
    return None


def _lines(md: cs.Cs, code: bytes, addr: int) -> list[str]:
    out = []
    for i, ins in enumerate(md.disasm(code, addr)):
        if i >= MAX_INSNS:
            break
        out.append(f"{ins.address:#012x}  {ins.bytes.hex():<20} {ins.mnemonic} {ins.op_str}".rstrip())
        if ins.mnemonic in ("ret", "retq", "hlt") and i > 4:
            break
    return out


def _region(b, va: int) -> bytes:
    try:
        return bytes(b.get_content_from_virtual_address(va, WINDOW))
    except Exception:  # noqa: BLE001
        return b""


def _one(b, rel: str, tag: str) -> list[Finding]:
    eng = _engine(b)
    if eng is None:
        return [Finding(STAGE, TOOL, "limitation", f"{tag}unsupported_arch",
                        str(b.abstract.header.architecture), subject=rel)]
    md, arch = eng
    out = []
    targets = [("entrypoint", b.entrypoint)] if b.entrypoint else []
    exports = [(f.name, f.address) for f in list(b.exported_functions)[:MAX_EXPORTS]]
    if not exports:   # object files / stripped dylibs: fall back to symbols inside the code section
        text = next((s for s in b.sections if s.name in ("__text", ".text")), None)
        if text is not None:
            lo, hi = text.virtual_address, text.virtual_address + text.size
            seen = set()
            for s in b.symbols:
                if s.name and not s.name.startswith(("ltmp", "$", ".L")) and lo <= s.value < hi and s.value not in seen:
                    seen.add(s.value)
                    exports.append((s.name, s.value))
                    if len(exports) >= MAX_EXPORTS:
                        break
    targets += [(f"export:{n}", a if a >= b.imagebase else b.imagebase + a) for n, a in exports]
    for label, va in targets:
        if thumb := (arch == "arm" and va & 1):
            md = cs.Cs(cs.CS_ARCH_ARM, cs.CS_MODE_THUMB)
            va &= ~1
        code = _region(b, va)
        if not code:
            continue
        lines = _lines(md, code, va)
        if lines:
            out.append(Finding(STAGE, TOOL, "disassembly", f"{tag}{label}",
                               {"arch": arch + (" (thumb)" if thumb else ""), "address": hex(va), "lines": lines},
                               Confidence.CONFIRMED, Provenance.PARSED, "linear disassembly from address", rel))
    return out


def analyze(path: Path, rel: str = "") -> list[Finding]:
    rel = rel or Path(path).name
    p = str(path)
    if lief.is_macho(p):
        fat = lief.MachO.parse(p)
        if fat is None:
            return []
        slices = list(fat)
        if len(slices) == 1:
            return _one(slices[0], rel, "")
        out = []
        for i, b in enumerate(slices):
            out += _one(b, rel, f"[slice{i}:{str(b.header.cpu_type).split('.')[-1]}] ")
        return out
    b = lief.parse(p)
    return _one(b, rel, "") if b is not None else []
