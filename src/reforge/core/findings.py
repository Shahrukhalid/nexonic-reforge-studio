"""Common findings schema shared by every analysis stage and tool adapter.

Every finding records *where it came from* (stage/tool), *what kind of evidence*
backs it, and a confidence level, so the UI and reports never present an
inference as a confirmed fact.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class Confidence(str, Enum):
    CONFIRMED = "confirmed"            # read directly from a structure (header, manifest, table)
    STRONG = "strongly_inferred"       # multiple or highly specific markers
    TENTATIVE = "tentative"            # single weak marker / heuristic
    UNKNOWN = "unknown"


class Provenance(str, Enum):
    EXTRACTED = "extracted_data"       # bytes/metadata copied out of the target
    PARSED = "parsed_structure"        # parsed from file format structures
    INFERRED = "inferred_behavior"     # heuristic interpretation
    DECOMPILED = "decompiled"          # decompiler output (never original source)
    GENERATED = "generated"            # newly generated code/text


@dataclass
class Finding:
    stage: str
    tool: str
    kind: str
    key: str
    value: Any
    confidence: Confidence = Confidence.CONFIRMED
    provenance: Provenance = Provenance.PARSED
    evidence: str = ""
    subject: str = ""                  # relative path of the analysed file
    extra: dict = field(default_factory=dict)

    def __post_init__(self) -> None:
        if isinstance(self.confidence, str) and not isinstance(self.confidence, Confidence):
            try:
                self.confidence = Confidence(self.confidence)
            except ValueError:
                self.confidence = Confidence.UNKNOWN
        if isinstance(self.provenance, str) and not isinstance(self.provenance, Provenance):
            try:
                self.provenance = Provenance(self.provenance)
            except ValueError:
                self.provenance = Provenance.PARSED

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Finding:
        d = dict(data)
        conf = d.get("confidence")
        if isinstance(conf, str):
            try:
                d["confidence"] = Confidence(conf)
            except ValueError:
                d["confidence"] = Confidence.UNKNOWN
        prov = d.get("provenance")
        if isinstance(prov, str):
            try:
                d["provenance"] = Provenance(prov)
            except ValueError:
                d["provenance"] = Provenance.PARSED
        return cls(**d)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["confidence"] = self.confidence.value
        d["provenance"] = self.provenance.value
        return d
