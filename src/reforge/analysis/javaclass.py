"""Java Class File (.class) bytecode and metadata analyzer.

Extracts classes, methods, signatures, field names, and constant pool string literals
directly from compiled JVM .class bytecode files in pure Python without external dependencies.
"""
from __future__ import annotations

import struct
from pathlib import Path
from typing import Any

from ..core.findings import Confidence, Finding, Provenance

STAGE = "bytecode"
TOOL = "reforge.javaclass"


def parse_class_file(data: bytes) -> dict[str, Any] | None:
    """Parse standard JVM .class file binary structure."""
    if len(data) < 10 or data[:4] != b"\xCA\xFE\xBA\xBE":
        return None

    offset = 4
    minor, major, cp_count = struct.unpack_from(">HHH", data, offset)
    offset += 6

    # 1-indexed constant pool
    cp: list[Any] = [None]
    idx = 1
    while idx < cp_count:
        if offset >= len(data):
            break
        tag = data[offset]
        offset += 1
        if tag == 1:  # Utf8
            length = struct.unpack_from(">H", data, offset)[0]
            offset += 2
            val = data[offset:offset + length].decode("utf-8", errors="replace")
            offset += length
            cp.append({"tag": 1, "value": val})
            idx += 1
        elif tag in (3, 4):  # Integer, Float
            offset += 4
            cp.append({"tag": tag})
            idx += 1
        elif tag in (5, 6):  # Long, Double
            offset += 8
            cp.append({"tag": tag})
            cp.append(None)  # Takes two entries in constant pool
            idx += 2
        elif tag == 7:  # Class
            name_idx = struct.unpack_from(">H", data, offset)[0]
            offset += 2
            cp.append({"tag": 7, "name_index": name_idx})
            idx += 1
        elif tag == 8:  # String
            str_idx = struct.unpack_from(">H", data, offset)[0]
            offset += 2
            cp.append({"tag": 8, "string_index": str_idx})
            idx += 1
        elif tag in (9, 10, 11):  # Fieldref, Methodref, InterfaceMethodref
            offset += 4
            cp.append({"tag": tag})
            idx += 1
        elif tag == 12:  # NameAndType
            n_idx, d_idx = struct.unpack_from(">HH", data, offset)
            offset += 4
            cp.append({"tag": 12, "name_index": n_idx, "desc_index": d_idx})
            idx += 1
        elif tag in (15, 16):  # MethodHandle, MethodType
            offset += 3 if tag == 15 else 2
            cp.append({"tag": tag})
            idx += 1
        elif tag in (17, 18):  # Dynamic, InvokeDynamic
            offset += 4
            cp.append({"tag": tag})
            idx += 1
        elif tag in (19, 20):  # Module, Package
            offset += 2
            cp.append({"tag": tag})
            idx += 1
        else:
            # Unknown tag, abort parsing constant pool
            break

    def get_utf8(entry_idx: int) -> str:
        if 0 < entry_idx < len(cp):
            entry = cp[entry_idx]
            if isinstance(entry, dict) and entry.get("tag") == 1:
                return entry["value"]
        return ""

    # Resolve string literals and class names
    string_constants: list[str] = []
    class_names: list[str] = []

    for item in cp:
        if isinstance(item, dict):
            if item.get("tag") == 8:  # String
                s = get_utf8(item.get("string_index", 0))
                if s:
                    string_constants.append(s)
            elif item.get("tag") == 7:  # Class
                c = get_utf8(item.get("name_index", 0))
                if c:
                    class_names.append(c.replace("/", "."))

    # Access flags, this_class, super_class
    if offset + 6 > len(data):
        return {
            "major": major,
            "minor": minor,
            "classes": class_names,
            "strings": string_constants,
            "methods": [],
        }

    offset += 6  # skip access_flags, this_class, super_class
    interfaces_count = struct.unpack_from(">H", data, offset)[0]
    offset += 2 + (interfaces_count * 2)

    # Skip fields
    if offset + 2 <= len(data):
        fields_count = struct.unpack_from(">H", data, offset)[0]
        offset += 2
        for _ in range(fields_count):
            if offset + 8 > len(data):
                break
            offset += 6
            attr_count = struct.unpack_from(">H", data, offset)[0]
            offset += 2
            for _ in range(attr_count):
                if offset + 6 > len(data):
                    break
                attr_len = struct.unpack_from(">I", data, offset + 2)[0]
                offset += 6 + attr_len

    # Parse methods
    methods: list[dict[str, str]] = []
    if offset + 2 <= len(data):
        methods_count = struct.unpack_from(">H", data, offset)[0]
        offset += 2
        for _ in range(methods_count):
            if offset + 8 > len(data):
                break
            _access, name_idx, desc_idx, attr_count = struct.unpack_from(">HHHH", data, offset)
            offset += 8
            m_name = get_utf8(name_idx)
            m_desc = get_utf8(desc_idx)
            if m_name and not m_name.startswith("<"):
                methods.append({"name": m_name, "descriptor": m_desc})

            for _ in range(attr_count):
                if offset + 6 > len(data):
                    break
                attr_len = struct.unpack_from(">I", data, offset + 2)[0]
                offset += 6 + attr_len

    return {
        "major": major,
        "minor": minor,
        "classes": class_names,
        "strings": string_constants,
        "methods": methods,
    }


def analyze(path: Path, rel: str = "") -> list[Finding]:
    """Analyze a Java .class file and extract classes, methods, and constant strings."""
    rel = rel or Path(path).name
    try:
        data = path.read_bytes()
    except Exception as e:
        return [Finding(STAGE, TOOL, "error", "class_read_failed", str(e), subject=rel)]

    info = parse_class_file(data)
    if not info:
        return [Finding(STAGE, TOOL, "error", "class_parse_failed", "Not a valid Java .class file", subject=rel)]

    findings: list[Finding] = []

    # Methods
    method_names = [m["name"] for m in info["methods"]]
    if method_names:
        findings.append(
            Finding(
                stage="functions",
                tool=TOOL,
                kind="function",
                key="java_methods",
                value=method_names,
                confidence=Confidence.CONFIRMED,
                provenance=Provenance.PARSED,
                evidence=f"Parsed {len(method_names)} methods from JVM method table",
                subject=rel,
            )
        )

    for m in info["methods"]:
        findings.append(
            Finding(
                stage="decompiled",
                tool=TOOL,
                kind="decompiled_functions",
                key=f"function:{m['name']}",
                value=m,
                confidence=Confidence.CONFIRMED,
                provenance=Provenance.PARSED,
                evidence=f"Method signature {m['descriptor']}",
                subject=rel,
            )
        )

    # Classes
    if info["classes"]:
        findings.append(
            Finding(
                stage="classes",
                tool=TOOL,
                kind="classes",
                key="jvm_classes",
                value=info["classes"][:50],
                confidence=Confidence.CONFIRMED,
                provenance=Provenance.PARSED,
                evidence="JVM Constant Pool Class entries",
                subject=rel,
            )
        )

    # Strings
    for s in set(info["strings"]):
        findings.append(
            Finding(
                stage="strings",
                tool=TOOL,
                kind="string",
                key="string",
                value=s,
                confidence=Confidence.CONFIRMED,
                provenance=Provenance.EXTRACTED,
                evidence="JVM Constant Pool Utf8 string literal",
                subject=rel,
            )
        )

    return findings
