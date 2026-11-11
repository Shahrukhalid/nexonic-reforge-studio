"""Ground Truth Benchmarking & Accuracy Evaluation Engine.

Evaluates recovered reverse-engineering findings against legally authorized, known
ground-truth reference applications. Measures real decompiler precision, recall,
false positives, false negatives, and explicitly documents missing information
and analysis limitations.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from ..core.findings import Finding
from .synthesizer import DecompilationSynthesizer, DecompiledFunction


@dataclass
class ExpectedFunction:
    name: str
    min_params: int = 0
    return_type: str = "int"
    is_export: bool = False
    required_strings: list[str] = field(default_factory=list)


@dataclass
class GroundTruthSpec:
    target_name: str
    target_format: str  # "PE", "ELF", "Mach-O", "Java", ".NET", "APK"
    expected_functions: list[ExpectedFunction] = field(default_factory=list)
    expected_strings: list[str] = field(default_factory=list)
    expected_imports: list[str] = field(default_factory=list)
    expected_exports: list[str] = field(default_factory=list)
    expected_endpoints: list[str] = field(default_factory=list)
    documented_limitations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class MetricBreakdown:
    category: str
    total_expected: int
    true_positives: list[str]
    false_positives: list[str]
    false_negatives: list[str]
    precision: float = 0.0
    recall: float = 0.0
    f1_score: float = 0.0

    def compute(self) -> None:
        tp = len(self.true_positives)
        fp = len(self.false_positives)
        fn = len(self.false_negatives)

        self.precision = round(tp / (tp + fp), 4) if (tp + fp) > 0 else 0.0
        self.recall = round(tp / (tp + fn), 4) if (tp + fn) > 0 else 0.0
        if (self.precision + self.recall) > 0:
            self.f1_score = round(2 * (self.precision * self.recall) / (self.precision + self.recall), 4)
        else:
            self.f1_score = 0.0


@dataclass
class GroundTruthReport:
    target_name: str
    target_format: str
    overall_accuracy: float
    functions_metric: MetricBreakdown
    strings_metric: MetricBreakdown
    endpoints_metric: MetricBreakdown
    verified_recovered_items: list[str] = field(default_factory=list)
    false_positive_items: list[str] = field(default_factory=list)
    missing_items: list[str] = field(default_factory=list)
    identified_limitations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class GroundTruthEvaluator:
    """Compares analysis findings against a documented GroundTruthSpec to assess real-world accuracy."""

    @classmethod
    def evaluate(
        cls,
        spec: GroundTruthSpec,
        findings: list[Finding | dict[str, Any]],
        synthesized_funcs: list[DecompiledFunction] | None = None,
    ) -> GroundTruthReport:
        """Run comprehensive ground-truth accuracy evaluation."""
        if synthesized_funcs is None:
            synthesized_funcs = DecompilationSynthesizer.synthesize_from_findings(findings, spec.target_name)

        raw_findings = [f.to_dict() if isinstance(f, Finding) else f for f in findings]

        # 1. Recovered function names
        recovered_func_names = set(f.name for f in synthesized_funcs)
        # Also include any functions explicitly recorded in findings
        for r in raw_findings:
            key = r.get("key", "")
            kind = r.get("kind", "")
            val = r.get("value")
            if "export:" in key:
                recovered_func_names.add(key.split("export:", 1)[1])
            elif "function:" in key:
                recovered_func_names.add(key.split("function:", 1)[1])
            elif "functions" in key or "methods" in key or kind in ("function", "exports"):
                if isinstance(val, list):
                    for fn_item in val:
                        if isinstance(fn_item, str):
                            recovered_func_names.add(fn_item)
                        elif isinstance(fn_item, dict) and "name" in fn_item:
                            recovered_func_names.add(fn_item["name"])
                elif isinstance(val, dict):
                    if "name" in val:
                        recovered_func_names.add(val["name"])
                    for fn_item in val.get("items", []):
                        if isinstance(fn_item, str):
                            recovered_func_names.add(fn_item)
                        elif isinstance(fn_item, dict) and "name" in fn_item:
                            recovered_func_names.add(fn_item["name"])
                elif isinstance(val, str):
                    recovered_func_names.add(val)

        # 2. Recovered strings
        recovered_strings = set()
        for r in raw_findings:
            if r.get("kind") == "string" and isinstance(r.get("value"), str):
                recovered_strings.add(r["value"])
            elif r.get("key") == "strings" and isinstance(r.get("value"), list):
                for s in r["value"]:
                    if isinstance(s, str):
                        recovered_strings.add(s)

        # 3. Recovered endpoints
        recovered_endpoints = set()
        for r in raw_findings:
            if r.get("kind") in ("network", "url", "endpoint"):
                val = r.get("value")
                if isinstance(val, str):
                    recovered_endpoints.add(val)
                elif isinstance(val, list):
                    recovered_endpoints.update(str(x) for x in val if isinstance(x, (str, int)))

        # Evaluate Functions
        def _match_fn(exp_name: str, candidate_names: set[str]) -> bool:
            if exp_name in candidate_names:
                return True
            for cand in candidate_names:
                if cand.endswith("." + exp_name) or cand.endswith("::" + exp_name):
                    return True
                base = cand.split("(", 1)[0].strip()
                if base == exp_name or base.endswith("." + exp_name) or base.endswith("::" + exp_name):
                    return True
            return False

        exp_funcs = set(ef.name for ef in spec.expected_functions)
        matched_funcs = sorted([ef for ef in exp_funcs if _match_fn(ef, recovered_func_names)])
        missing_funcs = sorted([ef for ef in exp_funcs if not _match_fn(ef, recovered_func_names)])
        extra_funcs = sorted([rf for rf in recovered_func_names if not any(_match_fn(ef, {rf}) for ef in exp_funcs)])

        func_breakdown = MetricBreakdown(
            category="Functions & Symbols",
            total_expected=len(exp_funcs),
            true_positives=matched_funcs,
            false_positives=extra_funcs,
            false_negatives=missing_funcs,
        )
        func_breakdown.compute()

        # Evaluate Strings
        exp_strings = set(spec.expected_strings)
        matched_strings = [s for s in exp_strings if any(s in rec for rec in recovered_strings)]
        missing_strings = [s for s in exp_strings if not any(s in rec for rec in recovered_strings)]
        extra_strings_sample = [s for s in recovered_strings if not any(exp in s for exp in exp_strings)][:10]

        str_breakdown = MetricBreakdown(
            category="Constant Strings",
            total_expected=len(exp_strings),
            true_positives=matched_strings,
            false_positives=extra_strings_sample,
            false_negatives=missing_strings,
        )
        str_breakdown.compute()

        # Evaluate Endpoints
        exp_endpoints = set(spec.expected_endpoints)
        matched_endpoints = [
            e for e in exp_endpoints
            if any(e in rec for rec in recovered_endpoints) or _match_fn(e, recovered_func_names)
        ]
        missing_endpoints = [e for e in exp_endpoints if e not in matched_endpoints]
        extra_endpoints = [e for e in recovered_endpoints if not any(exp in e for exp in exp_endpoints)]

        ep_breakdown = MetricBreakdown(
            category="Network Endpoints",
            total_expected=len(exp_endpoints),
            true_positives=matched_endpoints,
            false_positives=extra_endpoints,
            false_negatives=missing_endpoints,
        )
        ep_breakdown.compute()

        # Compute overall accuracy
        scores = [func_breakdown.f1_score]
        if exp_strings:
            scores.append(str_breakdown.f1_score)
        if exp_endpoints:
            scores.append(ep_breakdown.f1_score)
        overall_acc = round(sum(scores) / len(scores), 4) if scores else 1.0

        # Identified Limitations
        limitations = list(spec.documented_limitations)
        if missing_funcs:
            limitations.append(f"Inlined or stripped functions undetected: {', '.join(missing_funcs[:5])}")
        if missing_endpoints:
            limitations.append(f"Dynamic or encrypted endpoints undetected statically: {', '.join(missing_endpoints)}")
        if extra_funcs:
            limitations.append(f"Compiler runtime or library glue functions detected: {len(extra_funcs)} extra symbols")

        return GroundTruthReport(
            target_name=spec.target_name,
            target_format=spec.target_format,
            overall_accuracy=overall_acc,
            functions_metric=func_breakdown,
            strings_metric=str_breakdown,
            endpoints_metric=ep_breakdown,
            verified_recovered_items=matched_funcs + matched_strings + matched_endpoints,
            false_positive_items=extra_funcs[:10] + extra_endpoints,
            missing_items=missing_funcs + missing_strings + missing_endpoints,
            identified_limitations=limitations,
        )

    @classmethod
    def generate_markdown_report(cls, report: GroundTruthReport) -> str:
        """Render a formal Ground Truth Benchmark Report in GitHub Flavored Markdown."""
        lines = [
            "# Nexonic ReForge Studio — Ground Truth Evaluation Report",
            "",
            f"**Target Subject:** `{report.target_name}` ({report.target_format})  ",
            f"**Overall F1 Accuracy:** `{report.overall_accuracy * 100:.1f}%`  ",
            "",
            "## 1. Quantitative Accuracy Breakdown",
            "",
            "| Metric Category | Expected | True Positives | False Positives | False Negatives | Precision | Recall | F1 Score |",
            "|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|",
        ]

        for m in (report.functions_metric, report.strings_metric, report.endpoints_metric):
            lines.append(
                f"| **{m.category}** | {m.total_expected} | {len(m.true_positives)} | "
                f"{len(m.false_positives)} | {len(m.false_negatives)} | "
                f"{m.precision * 100:.1f}% | {m.recall * 100:.1f}% | {m.f1_score * 100:.1f}% |"
            )

        lines.extend([
            "",
            "## 2. Verified Recovered Features `[CONFIRMED]`",
            "",
        ])
        if report.verified_recovered_items:
            for item in report.verified_recovered_items:
                lines.append(f"- `[VERIFIED]` {item}")
        else:
            lines.append("_No ground-truth features verified in analysis findings._")

        lines.extend([
            "",
            "## 3. Discrepancies & Limitations `[CAUTION]`",
            "",
            "### Missing Features (False Negatives)",
        ])
        if report.missing_items:
            for item in report.missing_items:
                lines.append(f"- `[MISSING]` {item}")
        else:
            lines.append("_Zero missing ground-truth features._")

        lines.extend([
            "",
            "### Heuristic or Runtime False Positives",
        ])
        if report.false_positive_items:
            for item in report.false_positive_items:
                lines.append(f"- `[HEURISTIC / GLUE]` {item}")
        else:
            lines.append("_Zero false positives detected._")

        lines.extend([
            "",
            "### Ground Truth Analysis Boundaries",
        ])
        if report.identified_limitations:
            for lim in report.identified_limitations:
                lines.append(f"- {lim}")
        else:
            lines.append("_No analysis boundaries documented._")

        return "\n".join(lines)
