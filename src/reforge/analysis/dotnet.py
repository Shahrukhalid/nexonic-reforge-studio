""".NET assembly metadata via dnfile (MIT): assembly identity, references, types, P/Invoke imports,
resources. Parsed from CLR metadata tables only; no code is executed or decompiled here."""
from __future__ import annotations

from pathlib import Path

from ..core.findings import Confidence, Finding, Provenance

STAGE = "dotnet"
TOOL = "dnfile"
MAX_ITEMS = 2000


def _s(v) -> str:
    return "" if v is None else str(v)


def _rows(table) -> list:
    return list(table.rows) if table is not None and table.num_rows else []


def _ver(r) -> str:
    return f"{r.MajorVersion}.{r.MinorVersion}.{r.BuildNumber}.{r.RevisionNumber}"


def is_dotnet(path: Path) -> bool:
    """True if the PE has a CLR runtime header (structural check via LIEF)."""
    import lief

    from .binary import _has_clr
    try:
        b = lief.PE.parse(str(path))
        return b is not None and _has_clr(b)
    except Exception:  # noqa: BLE001
        return False


def analyze(path: Path, rel: str = "") -> list[Finding]:
    rel = rel or Path(path).name
    try:
        import dnfile
    except ImportError:
        return [Finding(STAGE, TOOL, "limitation", "dnfile_missing", "dnfile not installed", Confidence.CONFIRMED)]
    try:
        pe = dnfile.dnPE(str(path))
    except Exception as e:  # noqa: BLE001 - malformed input
        return [Finding(STAGE, TOOL, "error", "dotnet_parse_failed", str(e), subject=rel)]
    try:
        md = pe.net
        if md is None or md.mdtables is None:
            return [Finding(STAGE, TOOL, "error", "no_clr_metadata", "no CLR metadata streams", subject=rel)]
        t = md.mdtables
        out: list[Finding] = []
        asm = _rows(t.Assembly)
        ident = {"runtime_version": md.metadata.struct.Version.rstrip(b"\0").decode(errors="replace")
                 if md.metadata else None,
                 "il_only": bool(getattr(md.Flags, "CLR_ILONLY", False)),
                 "module": _s(_rows(t.Module)[0].Name) if _rows(t.Module) else None}
        if asm:
            a = asm[0]
            ident |= {"assembly": _s(a.Name), "version": _ver(a), "culture": _s(a.Culture) or "neutral"}
        out.append(Finding(STAGE, TOOL, "metadata", "dotnet_assembly", ident, subject=rel))
        refs = [{"name": _s(r.Name), "version": _ver(r)} for r in _rows(t.AssemblyRef)]
        out.append(Finding(STAGE, TOOL, "dependencies", "assembly_references", refs[:MAX_ITEMS], subject=rel))
        types = [f"{_s(r.TypeNamespace)}.{_s(r.TypeName)}".lstrip(".") for r in _rows(t.TypeDef)]
        ns: dict[str, int] = {}
        for ty in types:
            k = ty.rsplit(".", 1)[0] if "." in ty else "(global)"
            ns[k] = ns.get(k, 0) + 1
        out.append(Finding(STAGE, TOOL, "classes", "dotnet_types",
                           {"count": len(types), "methods": len(_rows(t.MethodDef)),
                            "namespaces": dict(sorted(ns.items(), key=lambda kv: -kv[1])[:60]),
                            "items": types[:MAX_ITEMS]}, subject=rel))
        pinv = []
        for r in _rows(t.ImplMap):
            scope = r.ImportScope.row if r.ImportScope is not None else None
            pinv.append({"function": _s(r.ImportName), "library": _s(scope.Name) if scope is not None else ""})
        if pinv:
            out.append(Finding(STAGE, TOOL, "imports", "pinvoke_imports", pinv[:MAX_ITEMS], Confidence.CONFIRMED,
                               Provenance.PARSED, "ImplMap table (native calls from managed code)", rel))
        res = [_s(r.Name) for r in _rows(t.ManifestResource)]
        if res:
            out.append(Finding(STAGE, TOOL, "resources", "manifest_resources", res[:MAX_ITEMS], subject=rel))
        return out
    finally:
        pe.close()
