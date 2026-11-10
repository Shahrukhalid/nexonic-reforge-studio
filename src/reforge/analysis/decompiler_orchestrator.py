"""Multi-Engine Decompilation Orchestration and Output Management."""
from __future__ import annotations

import difflib
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any

from ..core.findings import Confidence, Finding, Provenance
from .synthesizer import (
    GENUINE_DECOMPILER_BANNER,
    DecompilationSynthesizer,
)


class DecompilerEngine(str, Enum):
    AUTO = "auto"
    GHIDRA = "ghidra"
    JADX = "jadx"
    ILSPY = "ilspy"
    SYNTHESIZER = "synthesizer"


ENGINE_METADATA: dict[str, dict[str, Any]] = {
    DecompilerEngine.GHIDRA.value: {
        "name": "Ghidra Decompiler (NSA)",
        "version": "12.2 Headless",
        "type": "native",
        "description": "High-fidelity native C decompiler via headless Ghidra DecompInterface.",
        "confidence": Confidence.CONFIRMED.value,
        "provenance": Provenance.DECOMPILED.value,
        "is_genuine": True,
        "supported_profiles": ["pe", "elf", "macho", "raw_binary"],
    },
    DecompilerEngine.JADX.value: {
        "name": "JADX Java/Android Decompiler",
        "version": "1.5.x CLI",
        "type": "bytecode",
        "description": "Direct Dalvik DEX and Java bytecode decompiler producing clean Java source.",
        "confidence": Confidence.CONFIRMED.value,
        "provenance": Provenance.DECOMPILED.value,
        "is_genuine": True,
        "supported_profiles": ["apk", "dex", "jar", "class"],
    },
    DecompilerEngine.ILSPY.value: {
        "name": "ILSpy .NET Decompiler",
        "version": "8.x/9.x (ilspycmd)",
        "type": "cil",
        "description": "High-accuracy Common Intermediate Language (CIL) decompiler producing C# source.",
        "confidence": Confidence.CONFIRMED.value,
        "provenance": Provenance.DECOMPILED.value,
        "is_genuine": True,
        "supported_profiles": ["dotnet_pe", "cil", "assembly"],
    },
    DecompilerEngine.SYNTHESIZER.value: {
        "name": "Clean-Room Decompilation Synthesizer",
        "version": "v0.9.0 In-Process",
        "type": "heuristic",
        "description": "Multi-pass clean-room reconstruction synthesizing structured pseudocode from Capstone disassembly.",
        "confidence": Confidence.STRONG.value,
        "provenance": Provenance.INFERRED.value,
        "is_genuine": False,
        "supported_profiles": ["all"],
    },
}


@dataclass
class DecompilerOutput:
    engine: str
    function_name: str
    address: str
    code: str
    language: str = "c"
    confidence: str = Confidence.CONFIRMED.value
    confidence_score: float = 1.0
    provenance: str = Provenance.DECOMPILED.value
    is_genuine: bool = True
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class DecompilerOrchestrator:
    """Orchestrates multiple decompiler engines, extracts findings, and provides engine comparison."""

    @staticmethod
    def get_supported_engines() -> list[dict[str, Any]]:
        """Return metadata for all registered decompiler engines."""
        return [
            {"id": eid, **meta}
            for eid, meta in ENGINE_METADATA.items()
        ]

    @staticmethod
    def resolve_best_engine(profile: str, available_engines: set[str] | list[str]) -> str:
        """Determine the optimal decompiler engine given target profile and available engines."""
        avail = set(available_engines)
        prof = (profile or "").lower()

        if any(p in prof for p in ["apk", "dex", "android", "jar"]) and DecompilerEngine.JADX.value in avail:
            return DecompilerEngine.JADX.value
        if any(p in prof for p in ["dotnet", "cil", "csharp", ".net"]) and DecompilerEngine.ILSPY.value in avail:
            return DecompilerEngine.ILSPY.value
        if DecompilerEngine.GHIDRA.value in avail:
            return DecompilerEngine.GHIDRA.value
        return DecompilerEngine.SYNTHESIZER.value

    @classmethod
    def extract_engine_outputs(
        cls,
        findings: list[Finding | dict[str, Any]],
        target_subject: str = "",
    ) -> dict[str, dict[str, DecompilerOutput]]:
        """Extract all decompiled functions grouped by engine and function name.

        Returns:
            {
               "ghidra": {"func_a": DecompilerOutput, ...},
               "jadx": {"func_b": DecompilerOutput, ...},
               "synthesizer": {"func_a": DecompilerOutput, ...}
            }
        """
        results: dict[str, dict[str, DecompilerOutput]] = {
            DecompilerEngine.GHIDRA.value: {},
            DecompilerEngine.JADX.value: {},
            DecompilerEngine.ILSPY.value: {},
            DecompilerEngine.SYNTHESIZER.value: {},
        }

        # 1. Extract from tool findings
        for item in findings:
            f = item.to_dict() if isinstance(item, Finding) else item
            tool = f.get("tool", "").lower()
            category = f.get("kind", "") or f.get("category", "")
            subject = f.get("key", "") or f.get("subject", "")
            data = f.get("value") if isinstance(f.get("value"), dict) else (f.get("data") or {})

            if category == "decompiled":
                code = data.get("code", "")
                if not code:
                    continue

                if tool == "ghidra":
                    func_name = subject or data.get("name", "unnamed_function")
                    addr = data.get("entry", "0x0")
                    sig = data.get("signature", "")
                    banner = GENUINE_DECOMPILER_BANNER.format(
                        name=func_name,
                        address=addr,
                        size=len(code),
                        arch=data.get("arch", "x86-64"),
                        provenance=Provenance.DECOMPILED.value,
                        engine="Ghidra 12.2 Headless DecompInterface",
                    )
                    full_code = f"{banner}\n{sig}\n{code}" if sig and sig not in code else f"{banner}\n{code}"
                    results[DecompilerEngine.GHIDRA.value][func_name] = DecompilerOutput(
                        engine=DecompilerEngine.GHIDRA.value,
                        function_name=func_name,
                        address=addr,
                        code=full_code,
                        language="c",
                        confidence=Confidence.CONFIRMED.value,
                        confidence_score=1.0,
                        provenance=Provenance.DECOMPILED.value,
                        is_genuine=True,
                        metadata=data,
                    )

                elif tool == "jadx":
                    func_name = subject or data.get("file", "JavaClass")
                    results[DecompilerEngine.JADX.value][func_name] = DecompilerOutput(
                        engine=DecompilerEngine.JADX.value,
                        function_name=func_name,
                        address="0x0",
                        code=code,
                        language="java",
                        confidence=Confidence.CONFIRMED.value,
                        confidence_score=1.0,
                        provenance=Provenance.DECOMPILED.value,
                        is_genuine=True,
                        metadata=data,
                    )

                elif tool == "ilspy":
                    func_name = subject or data.get("file", "CSharpClass")
                    results[DecompilerEngine.ILSPY.value][func_name] = DecompilerOutput(
                        engine=DecompilerEngine.ILSPY.value,
                        function_name=func_name,
                        address="0x0",
                        code=code,
                        language="csharp",
                        confidence=Confidence.CONFIRMED.value,
                        confidence_score=1.0,
                        provenance=Provenance.DECOMPILED.value,
                        is_genuine=True,
                        metadata=data,
                    )

        # 2. Extract synthesized pseudocode from Capstone disassembly findings
        synth_funcs = DecompilationSynthesizer.synthesize_from_findings(findings, target_subject)
        for sf in synth_funcs:
            # We save the synthesizer output
            results[DecompilerEngine.SYNTHESIZER.value][sf.name] = DecompilerOutput(
                engine=DecompilerEngine.SYNTHESIZER.value,
                function_name=sf.name,
                address=sf.address,
                code=sf.pseudocode,
                language="c",
                confidence=sf.confidence,
                confidence_score=sf.confidence_score,
                provenance=sf.provenance,
                is_genuine=sf.is_verified_decompiler,
                metadata={
                    "cyclomatic_complexity": sf.cyclomatic_complexity,
                    "cfg_blocks": len(sf.cfg_blocks),
                    "callers": sf.callers,
                    "callees": sf.callees,
                },
            )

        return results

    @classmethod
    def compare_decompiler_outputs(
        cls,
        func_name: str,
        engine_a: str,
        engine_b: str,
        outputs: dict[str, dict[str, DecompilerOutput]],
    ) -> dict[str, Any]:
        """Perform side-by-side comparison and similarity calculation between two decompiler engine outputs."""
        out_a = outputs.get(engine_a, {}).get(func_name)
        out_b = outputs.get(engine_b, {}).get(func_name)

        if not out_a and not out_b:
            return {
                "function": func_name,
                "engine_a": engine_a,
                "engine_b": engine_b,
                "similarity": 0.0,
                "diff": f"No decompilation available for {func_name} in either engine.",
                "code_a": "",
                "code_b": "",
            }

        code_a = out_a.code if out_a else f"// [{engine_a.upper()}] No decompilation generated for {func_name}"
        code_b = out_b.code if out_b else f"// [{engine_b.upper()}] No decompilation generated for {func_name}"

        lines_a = code_a.splitlines(keepends=True)
        lines_b = code_b.splitlines(keepends=True)

        matcher = difflib.SequenceMatcher(None, lines_a, lines_b)
        similarity = round(matcher.ratio(), 4)

        diff_lines = list(
            difflib.unified_diff(
                lines_a,
                lines_b,
                fromfile=f"{engine_a}/{func_name}",
                tofile=f"{engine_b}/{func_name}",
            )
        )
        diff_str = "".join(diff_lines) or "Decompiler outputs are textually identical."

        return {
            "function": func_name,
            "engine_a": engine_a,
            "engine_b": engine_b,
            "similarity": similarity,
            "diff": diff_str,
            "code_a": code_a,
            "code_b": code_b,
        }
