"""Interactive Binary Diffing Engine: compares two binaries or project findings side-by-side."""
from __future__ import annotations

import difflib
import json
from dataclasses import asdict, dataclass, field
from typing import Any

from ..core.findings import Finding
from .synthesizer import DecompilationSynthesizer, DecompiledFunction


@dataclass
class FunctionDiffItem:
    name: str
    address_a: str | None
    address_b: str | None
    status: str  # 'identical', 'modified', 'added', 'removed'
    match_type: str  # 'exact_match', 'symbol_match', 'heuristic_match', 'unmatched'
    confidence: float
    similarity: float
    assembly_a: list[str] = field(default_factory=list)
    assembly_b: list[str] = field(default_factory=list)
    pseudocode_a: str = ""
    pseudocode_b: str = ""
    diff_unified: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class DiffResult:
    target_a: str
    target_b: str
    metadata_diff: dict[str, Any] = field(default_factory=dict)
    sections_diff: dict[str, Any] = field(default_factory=dict)
    imports_diff: dict[str, Any] = field(default_factory=dict)
    exports_diff: dict[str, Any] = field(default_factory=dict)
    functions: list[FunctionDiffItem] = field(default_factory=list)
    strings_diff: dict[str, Any] = field(default_factory=dict)
    overall_similarity: float = 1.0
    summary: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class BinaryDiffEngine:
    """Compares metadata, functions, disassembly, pseudocode, and resources between two targets."""

    @classmethod
    def compare_findings(
        cls,
        findings_a: list[Finding | dict[str, Any]],
        findings_b: list[Finding | dict[str, Any]],
        name_a: str = "Target A",
        name_b: str = "Target B",
    ) -> DiffResult:
        """Compare findings from two analyzed targets deterministically."""
        funcs_a = DecompilationSynthesizer.synthesize_from_findings(findings_a, name_a)
        funcs_b = DecompilationSynthesizer.synthesize_from_findings(findings_b, name_b)

        raw_a = [f.to_dict() if isinstance(f, Finding) else f for f in findings_a]
        raw_b = [f.to_dict() if isinstance(f, Finding) else f for f in findings_b]

        meta_diff = cls._diff_metadata(raw_a, raw_b)
        sec_diff = cls._diff_sections(raw_a, raw_b)
        imp_diff = cls._diff_lists(raw_a, raw_b, "imports")
        exp_diff = cls._diff_lists(raw_a, raw_b, "exports")
        str_diff = cls._diff_strings(raw_a, raw_b)

        func_diffs, overall_sim, summary = cls._diff_functions(funcs_a, funcs_b)

        return DiffResult(
            target_a=name_a,
            target_b=name_b,
            metadata_diff=meta_diff,
            sections_diff=sec_diff,
            imports_diff=imp_diff,
            exports_diff=exp_diff,
            functions=func_diffs,
            strings_diff=str_diff,
            overall_similarity=round(overall_sim, 4),
            summary=summary,
        )

    @classmethod
    def _diff_metadata(cls, raw_a: list[dict], raw_b: list[dict]) -> dict[str, Any]:
        hdr_a = next((r.get("value") for r in raw_a if r.get("key", "").endswith("header") and isinstance(r.get("value"), dict)), {})
        hdr_b = next((r.get("value") for r in raw_b if r.get("key", "").endswith("header") and isinstance(r.get("value"), dict)), {})

        keys = set(list(hdr_a.keys()) + list(hdr_b.keys()))
        diffs = {}
        for k in sorted(keys):
            val_a = hdr_a.get(k)
            val_b = hdr_b.get(k)
            diffs[k] = {"target_a": val_a, "target_b": val_b, "changed": val_a != val_b}
        return diffs

    @classmethod
    def _diff_sections(cls, raw_a: list[dict], raw_b: list[dict]) -> dict[str, Any]:
        secs_a = {s.get("name"): s for r in raw_a if r.get("key") == "sections" and isinstance(r.get("value"), list) for s in r["value"] if isinstance(s, dict)}
        secs_b = {s.get("name"): s for r in raw_b if r.get("key") == "sections" and isinstance(r.get("value"), list) for s in r["value"] if isinstance(s, dict)}

        names_a = set(secs_a.keys())
        names_b = set(secs_b.keys())

        common = sorted(names_a & names_b)
        added = sorted(names_b - names_a)
        removed = sorted(names_a - names_b)

        modified = []
        for name in common:
            sa, sb = secs_a[name], secs_b[name]
            size_delta = sb.get("size", 0) - sa.get("size", 0)
            ent_delta = (sb.get("entropy") or 0.0) - (sa.get("entropy") or 0.0)
            if size_delta != 0 or abs(ent_delta) > 0.01:
                modified.append({
                    "name": name,
                    "size_a": sa.get("size"),
                    "size_b": sb.get("size"),
                    "size_delta": size_delta,
                    "entropy_delta": round(ent_delta, 3),
                })

        return {"added": added, "removed": removed, "common_count": len(common), "modified": modified}

    @classmethod
    def _diff_lists(cls, raw_a: list[dict], raw_b: list[dict], kind: str) -> dict[str, Any]:
        items_a: set[str] = set()
        items_b: set[str] = set()
        for r in raw_a:
            if (kind in r.get("key", "") or kind in r.get("kind", "")) and isinstance(r.get("value"), list):
                items_a.update(str(x) for x in r["value"])
        for r in raw_b:
            if (kind in r.get("key", "") or kind in r.get("kind", "")) and isinstance(r.get("value"), list):
                items_b.update(str(x) for x in r["value"])

        return {
            "added": sorted(items_b - items_a),
            "removed": sorted(items_a - items_b),
            "common": sorted(items_a & items_b),
        }

    @classmethod
    def _diff_strings(cls, raw_a: list[dict], raw_b: list[dict]) -> dict[str, Any]:
        strs_a = set(r.get("value") for r in raw_a if r.get("kind") == "string" and isinstance(r.get("value"), str))
        strs_b = set(r.get("value") for r in raw_b if r.get("kind") == "string" and isinstance(r.get("value"), str))
        return {
            "added_count": len(strs_b - strs_a),
            "removed_count": len(strs_a - strs_b),
            "common_count": len(strs_a & strs_b),
        }

    @classmethod
    def _diff_functions(
        cls,
        funcs_a: list[DecompiledFunction],
        funcs_b: list[DecompiledFunction],
    ) -> tuple[list[FunctionDiffItem], float, dict[str, int]]:
        """Compare functions using deterministic matching followed by heuristic similarity."""
        map_a = {f.name: f for f in funcs_a}
        map_b = {f.name: f for f in funcs_b}

        addr_b = {f.address: f for f in funcs_b if f.address}

        diff_items: list[FunctionDiffItem] = []
        matched_b: set[str] = set()

        # Phase 1 & 2: Match by exact symbol name
        for name, fa in map_a.items():
            fb = map_b.get(name)
            if fb is not None:
                matched_b.add(fb.name)
                match_type = "exact_match" if fa.address == fb.address else "symbol_match"
                conf = 1.0 if match_type == "exact_match" else 0.95

                sim, udiff = cls._calc_code_similarity(fa, fb)
                status = "identical" if sim >= 0.999 else "modified"

                diff_items.append(
                    FunctionDiffItem(
                        name=name,
                        address_a=fa.address,
                        address_b=fb.address,
                        status=status,
                        match_type=match_type,
                        confidence=conf,
                        similarity=round(sim, 4),
                        assembly_a=fa.assembly_lines,
                        assembly_b=fb.assembly_lines,
                        pseudocode_a=fa.pseudocode,
                        pseudocode_b=fb.pseudocode,
                        diff_unified=udiff,
                    )
                )

        # Phase 3 & 4: Match remaining by address or instruction hash
        unmatched_a = [f for f in funcs_a if f.name not in [d.name for d in diff_items]]
        for fa in unmatched_a:
            fb = addr_b.get(fa.address)
            if fb is not None and fb.name not in matched_b:
                matched_b.add(fb.name)
                sim, udiff = cls._calc_code_similarity(fa, fb)
                diff_items.append(
                    FunctionDiffItem(
                        name=f"{fa.name} ~ {fb.name}",
                        address_a=fa.address,
                        address_b=fb.address,
                        status="identical" if sim >= 0.999 else "modified",
                        match_type="heuristic_match",
                        confidence=0.85,
                        similarity=round(sim, 4),
                        assembly_a=fa.assembly_lines,
                        assembly_b=fb.assembly_lines,
                        pseudocode_a=fa.pseudocode,
                        pseudocode_b=fb.pseudocode,
                        diff_unified=udiff,
                    )
                )
            else:
                # Removed in B
                diff_items.append(
                    FunctionDiffItem(
                        name=fa.name,
                        address_a=fa.address,
                        address_b=None,
                        status="removed",
                        match_type="unmatched",
                        confidence=1.0,
                        similarity=0.0,
                        assembly_a=fa.assembly_lines,
                        pseudocode_a=fa.pseudocode,
                    )
                )

        # Added in B
        for fb in funcs_b:
            if fb.name not in matched_b and fb.name not in [d.name for d in diff_items]:
                diff_items.append(
                    FunctionDiffItem(
                        name=fb.name,
                        address_a=None,
                        address_b=fb.address,
                        status="added",
                        match_type="unmatched",
                        confidence=1.0,
                        similarity=0.0,
                        assembly_b=fb.assembly_lines,
                        pseudocode_b=fb.pseudocode,
                    )
                )

        # Summary statistics
        counts = {"identical": 0, "modified": 0, "added": 0, "removed": 0}
        total_sim = 0.0
        for item in diff_items:
            counts[item.status] = counts.get(item.status, 0) + 1
            if item.status in ("identical", "modified"):
                total_sim += item.similarity

        overall_sim = (total_sim / max(1, len(diff_items))) if diff_items else 1.0

        return sorted(diff_items, key=lambda x: (x.status != "modified", x.status != "identical", x.name)), overall_sim, counts

    @classmethod
    def _calc_code_similarity(cls, fa: DecompiledFunction, fb: DecompiledFunction) -> tuple[float, str]:
        """Compute line similarity ratio and unified diff between two function implementations."""
        lines_a = (fa.pseudocode or "\n".join(fa.assembly_lines)).splitlines()
        lines_b = (fb.pseudocode or "\n".join(fb.assembly_lines)).splitlines()

        matcher = difflib.SequenceMatcher(None, lines_a, lines_b)
        ratio = matcher.ratio()

        udiff = "\n".join(
            difflib.unified_diff(
                lines_a,
                lines_b,
                fromfile=f"a/{fa.name} ({fa.address})",
                tofile=f"b/{fb.name} ({fb.address})",
                lineterm="",
            )
        )
        return ratio, udiff

    @classmethod
    def generate_diff_report(cls, diff: DiffResult, format: str = "markdown") -> str:
        """Generate an exportable comprehensive comparison report in Markdown or JSON format."""
        if format.lower() == "json":
            return json.dumps(diff.to_dict(), indent=2)

        lines: list[str] = [
            "# Nexonic ReForge Studio — Binary Comparison Report",
            "",
            f"**Target A:** `{diff.target_a}`  ",
            f"**Target B:** `{diff.target_b}`  ",
            f"**Overall Codebase Similarity:** `{diff.overall_similarity * 100:.2f}%`  ",
            "",
            "## 1. Executive Summary",
            f"- **Identical Functions:** {diff.summary.get('identical', 0)}",
            f"- **Modified Functions:** {diff.summary.get('modified', 0)}",
            f"- **Added Functions (+):** {diff.summary.get('added', 0)}",
            f"- **Removed Functions (-):** {diff.summary.get('removed', 0)}",
            "",
            "## 2. Metadata & Architecture Differences",
            "| Attribute | Target A | Target B | Status |",
            "| :--- | :--- | :--- | :--- |",
        ]

        for k, v in diff.metadata_diff.items():
            status = "CHANGED" if v.get("changed") else "MATCH"
            lines.append(f"| `{k}` | `{v.get('target_a')}` | `{v.get('target_b')}` | **{status}** |")

        lines.extend([
            "",
            "## 3. Function-Level Changes",
            "| Function | Target A Addr | Target B Addr | Match Type | Status | Similarity |",
            "| :--- | :--- | :--- | :--- | :--- | :--- |",
        ])

        for fn in diff.functions[:100]:
            lines.append(
                f"| `{fn.name}` | `{fn.address_a or '—'}` | `{fn.address_b or '—'}` | {fn.match_type} | **{fn.status.upper()}** | {fn.similarity * 100:.1f}% |"
            )

        lines.extend([
            "",
            "## 4. Import / Export Changes",
            f"- **Added Imports (+):** {len(diff.imports_diff.get('added', []))} APIs",
            f"- **Removed Imports (-):** {len(diff.imports_diff.get('removed', []))} APIs",
            f"- **Added Exports (+):** {len(diff.exports_diff.get('added', []))} APIs",
            f"- **Removed Exports (-):** {len(diff.exports_diff.get('removed', []))} APIs",
            "",
            "---",
            "*Generated by Nexonic ReForge Studio — Clean-Room Binary Verification Engine*",
        ])

        return "\n".join(lines)
