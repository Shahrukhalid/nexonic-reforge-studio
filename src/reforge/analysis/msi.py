"""Native Windows Installer (MSI) reader: summary information + database tables.

Uses olefile (BSD) for the compound-file container and decodes the MSI database
format directly (string pool, _Tables/_Columns, column-major table streams), so it
works on macOS/Linux/Windows without msitools. Nothing is installed or executed.
"""
from __future__ import annotations

import struct
from pathlib import Path

from ..core.findings import Confidence, Finding, Provenance

STAGE = "msi"
TOOL = "reforge.msi"
CHARSET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz._"
MSITYPE_STRING, MSITYPE_NULLABLE = 0x0800, 0x1000
KEY_TABLES = ("Property", "File", "Component", "Directory", "Feature", "Registry", "CustomAction",
              "ServiceInstall", "Shortcut", "Binary", "LaunchCondition", "Upgrade")
MAX_ROWS = 5000


def decode_stream_name(name: str) -> str:
    out = []
    for ch in name:
        c = ord(ch)
        if 0x3800 <= c < 0x4800:
            c -= 0x3800
            out.append(CHARSET[c & 0x3F])
            out.append(CHARSET[(c >> 6) & 0x3F])
        elif 0x4800 <= c < 0x4840:
            out.append(CHARSET[c - 0x4800])
        elif c == 0x4840:
            out.append("!")              # table stream prefix
        else:
            out.append(ch)
    return "".join(out)


class MsiDatabase:
    def __init__(self, path: Path):
        import olefile
        self.ole = olefile.OleFileIO(str(path))
        self.streams = {}
        for entry in self.ole.listdir(streams=True, storages=False):
            self.streams[decode_stream_name(entry[-1]) if len(entry) == 1 else "/".join(entry)] = entry
        self._load_strings()
        self._load_schema()

    def close(self):
        self.ole.close()

    def _raw(self, name: str) -> bytes:
        e = self.streams.get(name)
        return self.ole.openstream(e).read() if e else b""

    def _load_strings(self):
        pool, data = self._raw("!_StringPool"), self._raw("!_StringData")
        if len(pool) < 4:
            raise ValueError("no MSI string pool")
        self.codepage, flags = struct.unpack_from("<HH", pool, 0)
        self.long_refs = bool(flags & 0x8000)
        enc = {65001: "utf-8", 1252: "cp1252", 0: "cp1252"}.get(self.codepage, f"cp{self.codepage}")
        try:
            "".encode(enc)
        except LookupError:
            enc = "cp1252"
        self.strings, off, i = [""], 0, 4
        while i + 4 <= len(pool):
            ln, refs = struct.unpack_from("<HH", pool, i)
            i += 4
            if ln == 0 and refs != 0 and i + 4 <= len(pool):      # long string: (0, hi16) then (lo16, refs)
                hi = refs
                lo, refs = struct.unpack_from("<HH", pool, i)
                ln = (hi << 16) | lo
                i += 4
            self.strings.append(data[off:off + ln].decode(enc, "replace"))
            off += ln

    def _ref_width(self) -> int:
        return 3 if self.long_refs else 2

    def _read_columns(self, raw: bytes, types: list[int]) -> list[list]:
        widths = [self._ref_width() if t & MSITYPE_STRING else (2 if (t & 0xFF) <= 2 else 4) for t in types]
        rowsize = sum(widths)
        if rowsize == 0:
            return []
        n = min(len(raw) // rowsize, MAX_ROWS)
        cols, off = [], 0
        for t, w in zip(types, widths, strict=True):
            vals = []
            for r in range(n):
                p = off + r * w
                v = int.from_bytes(raw[p:p + w], "little")
                if t & MSITYPE_STRING:
                    vals.append(self.strings[v] if 0 < v < len(self.strings) else None)
                else:
                    vals.append(None if v == 0 else v - (0x8000 if w == 2 else 0x80000000))
            cols.append(vals)
            off += w * (len(raw) // rowsize)
        return [list(row) for row in zip(*cols, strict=True)]

    def _load_schema(self):
        rows = self._read_columns(self._raw("!_Columns"), [MSITYPE_STRING, 2, MSITYPE_STRING, 2])
        self.schema: dict[str, list[tuple[int, str, int]]] = {}
        for table, num, name, typ in rows:
            if table and name and num is not None and typ is not None:
                self.schema.setdefault(table, []).append((num, name, typ))
        for cols in self.schema.values():
            cols.sort()

    def tables(self) -> list[str]:
        names = {s[1:] for s in self.streams if s.startswith("!") and not s.startswith("!_")}
        return sorted(set(self.schema) | names)

    def table(self, name: str) -> list[dict]:
        cols = self.schema.get(name)
        if not cols:
            return []
        rows = self._read_columns(self._raw("!" + name), [c[2] for c in cols])
        return [{c[1]: v for c, v in zip(cols, row, strict=True)} for row in rows]

    def summary(self) -> dict:
        m = self.ole.get_metadata()
        keys = ("title", "subject", "author", "keywords", "comments", "template", "revision_number",
                "create_time", "creating_application", "security")
        out = {}
        for k in keys:
            v = getattr(m, k, None)
            if v not in (None, b"", ""):
                out[k] = v.decode("utf-8", "replace") if isinstance(v, bytes) else str(v)
        if "revision_number" in out:
            out["package_code"] = out.pop("revision_number")
        if "template" in out:
            out["platform_languages"] = out.pop("template")
        return out


def analyze(path: Path, rel: str = "") -> list[Finding]:
    rel = rel or Path(path).name
    try:
        db = MsiDatabase(path)
    except Exception as e:  # noqa: BLE001 - malformed input
        return [Finding(STAGE, TOOL, "error", "msi_parse_failed", str(e), subject=rel)]
    try:
        out = [Finding(STAGE, TOOL, "metadata", "msi_summary", db.summary(), subject=rel,
                       evidence="\\x05SummaryInformation stream")]
        props = {r.get("Property"): r.get("Value") for r in db.table("Property") if r.get("Property")}
        keep = ("ProductName", "ProductVersion", "Manufacturer", "ProductCode", "UpgradeCode", "ProductLanguage",
                "ALLUSERS", "ARPURLINFOABOUT", "ARPHELPLINK")
        out.append(Finding(STAGE, TOOL, "metadata", "msi_product", {k: props[k] for k in keep if k in props},
                           subject=rel, evidence="Property table"))
        out.append(Finding(STAGE, TOOL, "inventory", "msi_tables",
                           {t: len(db.table(t)) for t in db.tables()}, subject=rel))
        for t in KEY_TABLES[1:]:
            rows = db.table(t)
            if rows:
                kind = "security" if t in ("CustomAction", "ServiceInstall") else "msi_table"
                out.append(Finding(STAGE, TOOL, kind, f"msi_{t}", rows[:500],
                                   Confidence.CONFIRMED, Provenance.PARSED,
                                   "CustomAction/ServiceInstall run code at install time" if kind == "security"
                                   else f"{t} table", rel))
        return out
    finally:
        db.close()
