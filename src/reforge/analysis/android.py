"""Native Android decoders: binary XML (AXML) manifests and DEX headers / class lists.

Pure Python, bounds-checked, no external tools. Everything here is parsed from
the file's own structures (Provenance.PARSED); risk notes are inferred.
"""
from __future__ import annotations

import struct
from pathlib import Path

from ..core.findings import Confidence, Finding, Provenance

STAGE = "android"
TOOL = "reforge.android"

RES_STRING_POOL, RES_XML, RES_XML_RESOURCE_MAP = 0x0001, 0x0003, 0x0180
RES_XML_START_NS, RES_XML_END_NS, RES_XML_START_EL, RES_XML_END_EL, RES_XML_CDATA = 0x0100, 0x0101, 0x0102, 0x0103, 0x0104
ANDROID_NS = "http://schemas.android.com/apk/res/android"
MAX_ELEMENTS = 50_000

# attribute resource ids -> names (used when obfuscators blank the attribute name strings)
ATTR_IDS = {0x01010003: "name", 0x01010010: "exported", 0x0101021B: "versionCode", 0x0101021C: "versionName",
            0x0101020C: "minSdkVersion", 0x01010270: "targetSdkVersion", 0x0101000F: "debuggable",
            0x01010280: "allowBackup", 0x01010001: "label", 0x01010018: "authorities", 0x01010006: "permission",
            0x01010002: "icon", 0x01010000: "theme", 0x010104EC: "usesCleartextTraffic"}

DANGEROUS = {"READ_CALENDAR", "WRITE_CALENDAR", "CAMERA", "READ_CONTACTS", "WRITE_CONTACTS", "GET_ACCOUNTS",
             "ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION", "ACCESS_BACKGROUND_LOCATION", "RECORD_AUDIO",
             "READ_PHONE_STATE", "READ_PHONE_NUMBERS", "CALL_PHONE", "READ_CALL_LOG", "WRITE_CALL_LOG",
             "ADD_VOICEMAIL", "USE_SIP", "BODY_SENSORS", "SEND_SMS", "RECEIVE_SMS", "READ_SMS", "RECEIVE_WAP_PUSH",
             "RECEIVE_MMS", "READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE", "READ_MEDIA_IMAGES",
             "READ_MEDIA_VIDEO", "READ_MEDIA_AUDIO", "POST_NOTIFICATIONS", "NEARBY_WIFI_DEVICES", "BLUETOOTH_SCAN",
             "BLUETOOTH_CONNECT", "ACTIVITY_RECOGNITION", "SYSTEM_ALERT_WINDOW", "REQUEST_INSTALL_PACKAGES"}


class AxmlError(ValueError):
    pass


def _string_pool(buf: bytes, off: int) -> list[str]:
    _, hsize, size = struct.unpack_from("<HHI", buf, off)
    count, _styles, flags, s_start, _ = struct.unpack_from("<IIIII", buf, off + 8)
    if count > 500_000 or off + size > len(buf):
        raise AxmlError("string pool out of bounds")
    utf8 = bool(flags & 0x100)
    offsets = struct.unpack_from(f"<{count}I", buf, off + hsize)
    base = off + s_start
    out = []
    for o in offsets:
        p = base + o
        if p >= len(buf):
            out.append("")
            continue
        if utf8:
            n = buf[p]
            p += 2 if n & 0x80 else 1          # utf-16 length (skipped)
            n = buf[p]
            if n & 0x80:
                n = ((n & 0x7F) << 8) | buf[p + 1]
                p += 1
            p += 1
            out.append(buf[p:p + n].decode("utf-8", "replace"))
        else:
            n = struct.unpack_from("<H", buf, p)[0]
            p += 2
            if n & 0x8000:
                n = ((n & 0x7FFF) << 16) | struct.unpack_from("<H", buf, p)[0]
                p += 2
            out.append(buf[p:p + n * 2].decode("utf-16le", "replace"))
    return out


def _value(dtype: int, data: int, strings: list[str]):
    if dtype == 0x03:
        return strings[data] if data < len(strings) else ""
    if dtype == 0x12:
        return data != 0
    if dtype in (0x10, 0x11):
        return struct.unpack("<i", struct.pack("<I", data))[0]
    if dtype == 0x01:
        return f"@0x{data:08x}"
    if dtype == 0x02:
        return f"?0x{data:08x}"
    return f"0x{data:x}"


def parse_axml(buf: bytes) -> dict:
    """Decode Android binary XML into a nested {"tag", "attrs", "children"} tree."""
    if len(buf) < 8 or struct.unpack_from("<H", buf, 0)[0] != RES_XML:
        raise AxmlError("not binary XML")
    strings: list[str] = []
    res_ids: list[int] = []
    root = {"tag": "#document", "attrs": {}, "children": []}
    stack = [root]
    off = struct.unpack_from("<H", buf, 2)[0]
    elements = 0
    while off + 8 <= len(buf):
        ctype, hsize, csize = struct.unpack_from("<HHI", buf, off)
        if csize < 8 or off + csize > len(buf):
            raise AxmlError(f"bad chunk at {off}")
        if ctype == RES_STRING_POOL:
            strings = _string_pool(buf, off)
        elif ctype == RES_XML_RESOURCE_MAP:
            n = (csize - hsize) // 4
            res_ids = list(struct.unpack_from(f"<{n}I", buf, off + hsize))
        elif ctype == RES_XML_START_EL:
            elements += 1
            if elements > MAX_ELEMENTS:
                raise AxmlError("too many elements")
            ext = off + hsize
            _ns, name, a_start, a_size, a_count = struct.unpack_from("<IIHHH", buf, ext)
            el = {"tag": strings[name] if name < len(strings) else "?", "attrs": {}, "children": []}
            for i in range(a_count):
                a = ext + a_start + i * a_size
                ans, aname, _raw, _sz, _r0, dtype, data = struct.unpack_from("<IIIHBBI", buf, a)
                key = strings[aname] if aname < len(strings) else ""
                if not key and aname < len(res_ids):
                    key = ATTR_IDS.get(res_ids[aname], f"attr_0x{res_ids[aname]:08x}")
                prefix = "android:" if ans < len(strings) and strings[ans] == ANDROID_NS else ""
                el["attrs"][prefix + key] = _value(dtype, data, strings)
            stack[-1]["children"].append(el)
            stack.append(el)
        elif ctype == RES_XML_END_EL and len(stack) > 1:
            stack.pop()
        off += csize
    return root


def to_xml(node: dict, depth: int = 0) -> str:
    pad = "  " * depth
    def fmt(v):
        return str(v).lower() if isinstance(v, bool) else v
    attrs = "".join(f' {k}="{fmt(v)}"' for k, v in node["attrs"].items())
    if node["tag"] == "#document":
        return "\n".join(to_xml(c, 0) for c in node["children"])
    if not node["children"]:
        return f"{pad}<{node['tag']}{attrs}/>"
    inner = "\n".join(to_xml(c, depth + 1) for c in node["children"])
    return f"{pad}<{node['tag']}{attrs}>\n{inner}\n{pad}</{node['tag']}>"


def _walk(node: dict):
    for c in node["children"]:
        yield c
        yield from _walk(c)


def manifest_summary(tree: dict) -> dict:
    man = next((n for n in tree["children"] if n["tag"] == "manifest"), None)
    if man is None:
        raise AxmlError("no <manifest> root")
    a = man["attrs"]
    out = {"package": a.get("package"), "versionCode": a.get("android:versionCode"),
           "versionName": a.get("android:versionName"), "permissions": [], "components": [], "sdk": {}}
    app = {}
    for n in _walk(man):
        t, at = n["tag"], n["attrs"]
        if t in ("uses-permission", "uses-permission-sdk-23"):
            out["permissions"].append(at.get("android:name"))
        elif t == "uses-sdk":
            out["sdk"] = {k.split(":")[-1]: v for k, v in at.items()}
        elif t == "application":
            app = {k.split(":")[-1]: v for k, v in at.items()}
        elif t in ("activity", "activity-alias", "service", "receiver", "provider"):
            has_filter = any(c["tag"] == "intent-filter" for c in n["children"])
            exported = at.get("android:exported")
            out["components"].append({"type": t, "name": at.get("android:name"),
                                      "exported": exported if exported is not None else ("implicit" if has_filter else False),
                                      "permission": at.get("android:permission"),
                                      "intent_filter": has_filter})
    out["application"] = app
    return out


def risk_notes(s: dict) -> list[str]:
    notes = []
    dang = sorted({p.rsplit(".", 1)[-1] for p in s["permissions"] if p} & DANGEROUS)
    if dang:
        notes.append("dangerous permissions: " + ", ".join(dang))
    app = s.get("application", {})
    if app.get("debuggable") is True:
        notes.append("application is debuggable")
    if app.get("allowBackup") is not False:
        notes.append("allowBackup not disabled (app data can be backed up)")
    if app.get("usesCleartextTraffic") is True:
        notes.append("cleartext (HTTP) traffic allowed")
    for c in s["components"]:
        if c["exported"] in (True, "implicit") and not c["permission"]:
            notes.append(f"exported {c['type']} without permission: {c['name']}")
    return notes


# ------------------------------------------------------------------ DEX
def _uleb(buf: bytes, p: int) -> tuple[int, int]:
    r = shift = 0
    while True:
        b = buf[p]
        p += 1
        r |= (b & 0x7F) << shift
        if not b & 0x80:
            return r, p
        shift += 7
        if shift > 35:
            raise ValueError("bad uleb128")


def parse_dex(buf: bytes, max_classes: int = 5000) -> dict:
    if buf[:4] != b"dex\n" or len(buf) < 0x70:
        raise ValueError("not a DEX file")
    (str_n, str_off, type_n, type_off, proto_n, _po, field_n, _fo, meth_n, _mo, cls_n, cls_off) = \
        struct.unpack_from("<12I", buf, 0x38)

    def string(i: int) -> str:
        o = struct.unpack_from("<I", buf, str_off + 4 * i)[0]
        _n, p = _uleb(buf, o)
        e = buf.index(b"\0", p)
        return buf[p:e].decode("utf-8", "replace")      # MUTF-8 ~ UTF-8 for display

    def type_name(i: int) -> str:
        d = string(struct.unpack_from("<I", buf, type_off + 4 * i)[0])
        return d[1:-1].replace("/", ".") if d.startswith("L") else d

    classes = []
    for i in range(min(cls_n, max_classes)):
        cidx = struct.unpack_from("<I", buf, cls_off + 32 * i)[0]
        classes.append(type_name(cidx))
    return {"version": buf[4:7].decode(errors="replace"), "strings": str_n, "types": type_n, "protos": proto_n,
            "fields": field_n, "methods": meth_n, "classes": cls_n, "class_names": classes}


def dex_strings(buf: bytes, limit: int = 20000) -> list[str]:
    str_n, str_off = struct.unpack_from("<II", buf, 0x38)
    out = []
    for i in range(min(str_n, limit)):
        o = struct.unpack_from("<I", buf, str_off + 4 * i)[0]
        _n, p = _uleb(buf, o)
        e = buf.index(b"\0", p)
        out.append(buf[p:e].decode("utf-8", "replace"))
    return out


# ------------------------------------------------------------------ findings
def manifest_findings(data: bytes, rel: str = "AndroidManifest.xml") -> list[Finding]:
    try:
        tree = parse_axml(data)
        s = manifest_summary(tree)
    except (AxmlError, struct.error, IndexError) as e:
        return [Finding(STAGE, TOOL, "error", "manifest_decode_failed", str(e), subject=rel)]
    out = [Finding(STAGE, TOOL, "metadata", "android_manifest",
                   {k: s[k] for k in ("package", "versionCode", "versionName", "sdk", "application")},
                   Confidence.CONFIRMED, Provenance.PARSED, "decoded binary AndroidManifest.xml", rel),
           Finding(STAGE, TOOL, "permissions", "android_permissions", s["permissions"], subject=rel),
           Finding(STAGE, TOOL, "components", "android_components", s["components"], subject=rel),
           Finding(STAGE, TOOL, "decoded", "manifest_xml", {"code": to_xml(tree)}, subject=rel,
                   provenance=Provenance.PARSED, evidence="re-serialised from binary XML")]
    notes = risk_notes(s)
    if notes:
        out.append(Finding(STAGE, TOOL, "security", "manifest_risks", notes, Confidence.STRONG,
                           Provenance.INFERRED, "static manifest rules", rel))
    return out


def dex_findings(path: Path, rel: str) -> list[Finding]:
    buf = Path(path).read_bytes()
    try:
        d = parse_dex(buf)
    except (ValueError, struct.error, IndexError) as e:
        return [Finding(STAGE, TOOL, "error", "dex_parse_failed", str(e), subject=rel)]
    pkgs: dict[str, int] = {}
    for c in d["class_names"]:
        pkg = c.rsplit(".", 1)[0] if "." in c else "(default)"
        pkgs[pkg] = pkgs.get(pkg, 0) + 1
    top = dict(sorted(pkgs.items(), key=lambda kv: -kv[1])[:60])
    names = d.pop("class_names")
    return [Finding(STAGE, TOOL, "dex", "dex_header", d, subject=rel),
            Finding(STAGE, TOOL, "classes", "dex_classes", {"count": len(names), "packages": top,
                    "items": names[:1000]}, subject=rel)]
