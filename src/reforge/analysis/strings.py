"""Embedded string extraction (ASCII + UTF-16LE) and indicator classification."""
from __future__ import annotations

import re
from pathlib import Path

from ..core.findings import Confidence, Finding, Provenance

STAGE = "strings"
TOOL = "reforge.strings"

ASCII_RE = re.compile(rb"[\x20-\x7e]{6,}")
UTF16_RE = re.compile(rb"(?:[\x20-\x7e]\x00){6,}")
URL_RE = re.compile(r"\b(?:https?|wss?|ftp)://[A-Za-z0-9.\-]+(?::\d+)?(?:/[^\s\"'<>`]*)?")
DOMAIN_RE = re.compile(r"\b(?:[a-z0-9-]{1,63}\.)+(?:com|net|org|io|dev|app|co|ai|cloud|gov|edu)\b", re.IGNORECASE)
IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
APIPATH_RE = re.compile(r"(?<![A-Za-z0-9])/(?:api|v\d|graphql|rest|oauth2?|auth)(?:/[A-Za-z0-9_\-{}.:]+)*")
WINPATH_RE = re.compile(r"\b[A-Za-z]:\\[^\"*?<>|\r\n\t]{3,}")
REGKEY_RE = re.compile(r"\b(?:HKEY_[A-Z_]+|HKLM|HKCU)\\[^\s\"]+")
SQL_RE = re.compile(r"\b(?:CREATE TABLE|INSERT INTO|SELECT .{1,80} FROM|ALTER TABLE)\b", re.IGNORECASE)
SECRETISH_RE = re.compile(r"(?:AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_\-]{35}|sk-[A-Za-z0-9]{20,}|-----BEGIN [A-Z ]*PRIVATE KEY)")

MAX_SCAN = 128 * 1024 * 1024
CAP = 500


def extract(path: Path, limit: int = MAX_SCAN) -> list[str]:
    with open(path, "rb") as f:
        data = f.read(limit)
    out = [m.group().decode("ascii") for m in ASCII_RE.finditer(data)]
    out += [m.group().decode("utf-16le") for m in UTF16_RE.finditer(data)]
    return out


def analyze(path: Path, rel: str = "") -> list[Finding]:
    rel = rel or path.name
    strs = extract(path)
    cats: dict[str, set[str]] = {k: set() for k in ("urls", "domains", "ipv4", "api_paths", "windows_paths",
                                                       "registry_keys", "sql", "possible_secrets")}
    for s in strs:
        for k, rx in (("urls", URL_RE), ("ipv4", IPV4_RE), ("api_paths", APIPATH_RE), ("windows_paths", WINPATH_RE),
                      ("registry_keys", REGKEY_RE), ("sql", SQL_RE)):
            for m in rx.findall(s):
                if len(cats[k]) < CAP:
                    cats[k].add(m)
        for m in DOMAIN_RE.findall(s):
            if len(cats["domains"]) < CAP:
                cats["domains"].add(m.lower())
        if SECRETISH_RE.search(s):
            # never store the secret itself; record only that one exists
            cats["possible_secrets"].add(f"pattern match (redacted) len={len(s)}")
    cats["ipv4"] = {ip for ip in cats["ipv4"] if not ip.startswith(("0.", "255."))}
    f = [Finding(STAGE, TOOL, "strings", "summary", {"total": len(strs)}, subject=rel, provenance=Provenance.EXTRACTED)]
    for k, v in cats.items():
        if v:
            conf = Confidence.CONFIRMED if k != "possible_secrets" else Confidence.TENTATIVE
            kind = "network" if k in ("urls", "domains", "ipv4", "api_paths") else "indicators"
            f.append(Finding(STAGE, TOOL, kind, k, sorted(v), conf, Provenance.EXTRACTED,
                             "present as embedded strings; reachability not verified", rel))
    return f
