"""Implementation Task Planner & Human Review Checklist Engine.

Transforms evidence-based functional specifications and verified binary findings
into actionable, discrete software implementation tasks with acceptance criteria,
explicit evidence references, and mandatory human review requirements for unknown
or unverified behavior.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from ..core.findings import Finding


@dataclass
class ImplementationTask:
    id: str
    title: str
    category: str  # "architecture", "core_logic", "data_models", "interface_contract", "security_safety", "testing_validation"
    description: str
    evidence_sources: list[str] = field(default_factory=list)
    acceptance_criteria: list[str] = field(default_factory=list)
    dependencies: list[str] = field(default_factory=list)
    requires_human_review: bool = False
    status: str = "pending"  # "pending", "reviewed", "in_progress", "completed"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class HumanReviewItem:
    id: str
    item: str
    reason: str
    evidence_status: str  # "UNVERIFIED_DATA", "UNKNOWN_FUNCTIONALITY", "HEURISTIC_INFERENCE"
    recommended_action: str
    reviewed: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class TaskPlanner:
    """Derives discrete, evidence-backed implementation tasks and human review checklists from specifications and findings."""

    @classmethod
    def generate_plan(
        cls,
        spec: str,
        findings: list[Finding | dict[str, Any]],
        project_name: str = "TargetApp",
        tech_stack: str = "python",
    ) -> tuple[list[ImplementationTask], list[HumanReviewItem]]:
        """Generate structured tasks and review items strictly bounded by observed evidence."""
        raw_findings = [f.to_dict() if isinstance(f, Finding) else f for f in findings]

        tasks: list[ImplementationTask] = []
        reviews: list[HumanReviewItem] = []

        # 1. Base Architecture Task (Always verified from target binary headers)
        arch_evidence = []
        for r in raw_findings:
            if "header" in r.get("key", ""):
                arch_evidence.append(f"{r.get('tool', 'binary')}:{r.get('key')}")

        tasks.append(
            ImplementationTask(
                id="TASK-01-ARCH",
                title=f"Scaffold clean-room {tech_stack.capitalize()} project architecture",
                category="architecture",
                description=(
                    f"Initialize an independent clean-room codebase for {project_name} "
                    f"using target tech stack '{tech_stack}' with strict namespace separation."
                ),
                evidence_sources=arch_evidence or ["binary:platform_format"],
                acceptance_criteria=[
                    "Project directory layout follows standard ecosystem conventions.",
                    "Clean-room separation: Zero copied target binary code or proprietary byte sequences.",
                    "Module initialization and config parser execute without external dependencies.",
                ],
                dependencies=[],
                requires_human_review=False,
            )
        )

        # 2. Extract Recovered Functions & Core Logic Tasks
        funcs_found: list[dict[str, Any]] = []
        for r in raw_findings:
            if r.get("kind") in ("decompiled", "decompiled_synthesized") and isinstance(r.get("value"), dict):
                funcs_found.append(r["value"])
            elif "export:" in r.get("key", ""):
                funcs_found.append({"name": r.get("key").split("export:", 1)[1], "address": "export"})

        task_idx = 2
        for fn in funcs_found[:15]:  # limit top discrete function tasks
            fname = fn.get("name", "func")
            faddr = fn.get("address", "unknown")
            is_verified = fn.get("is_verified_decompiler", False)
            complexity = fn.get("cyclomatic_complexity", 1)

            t = ImplementationTask(
                id=f"TASK-{task_idx:02d}-FUNC-{fname.upper()}",
                title=f"Implement independent function logic for '{fname}'",
                category="core_logic",
                description=(
                    f"Implement clean-room functional logic equivalent to observed behavior of '{fname}' "
                    f"discovered at address {faddr} (cyclomatic complexity: {complexity})."
                ),
                evidence_sources=[f"synthesizer:{fname}@{faddr}"],
                acceptance_criteria=[
                    f"Signature matches observed parameters and return type for {fname}.",
                    "Handles boundary edge cases identified in control flow blocks.",
                    "Unit tests verify contract behavior against ground-truth mock inputs.",
                ],
                dependencies=["TASK-01-ARCH"],
                requires_human_review=not is_verified,
            )
            tasks.append(t)
            task_idx += 1

        # 3. Network & Integration Tasks (Only if REAL endpoints were observed)
        observed_endpoints: set[str] = set()
        for r in raw_findings:
            if r.get("kind") in ("network", "url", "endpoint"):
                val = r.get("value")
                if isinstance(val, str) and val.startswith(("http://", "https://", "ws://")):
                    observed_endpoints.add(val)
                elif isinstance(val, list):
                    for item in val:
                        if isinstance(item, str) and item.startswith(("http://", "https://", "ws://")):
                            observed_endpoints.add(item)

        if observed_endpoints:
            tasks.append(
                ImplementationTask(
                    id=f"TASK-{task_idx:02d}-NET-CLIENT",
                    title="Implement service client with isolated mock boundaries",
                    category="interface_contract",
                    description=(
                        f"Implement client adapter for observed external communication targets: "
                        f"{', '.join(sorted(observed_endpoints)[:3])}."
                    ),
                    evidence_sources=[f"network:endpoints:{len(observed_endpoints)}_detected"],
                    acceptance_criteria=[
                        "Client communicates via configurable base URL without hardcoded host addresses.",
                        "All network interactions must provide offline unit test mocks.",
                        "Proper timeout and retry policies implemented.",
                    ],
                    dependencies=["TASK-01-ARCH"],
                    requires_human_review=True,
                )
            )
            task_idx += 1

        # 4. Behavioral Testing Task
        tasks.append(
            ImplementationTask(
                id=f"TASK-{task_idx:02d}-TEST-SUITE",
                title="Synthesize and run clean-room behavioral validation suite",
                category="testing_validation",
                description="Run multi-stack behavioral tests verifying confirmed contracts and mock boundaries.",
                evidence_sources=["reconstruct:tests_gen"],
                acceptance_criteria=[
                    "All verified contract tests pass 100%.",
                    "Mock boundaries successfully isolate network and filesystem interactions.",
                    "Zero host execution of analyzed binary during test execution.",
                ],
                dependencies=["TASK-01-ARCH"],
                requires_human_review=False,
            )
        )

        # 5. Extract Human Review Checklist Items
        # A. Unverified endpoints
        review_idx = 1
        for ep in sorted(observed_endpoints):
            reviews.append(
                HumanReviewItem(
                    id=f"REV-{review_idx:02d}-ENDPOINT",
                    item=f"Verify authorization & payload format for endpoint '{ep}'",
                    reason="Static analysis detected URL string, but protocol schema and authentication credentials cannot be determined from binary text alone.",
                    evidence_status="UNVERIFIED_DATA",
                    recommended_action="Confirm API contract and security authorization with service owner before deploying integration client.",
                )
            )
            review_idx += 1

        # B. Check for heuristic / tentative inferences in specification
        if "[INFERRED BEHAVIOR" in spec or "[UNKNOWN FUNCTIONALITY" in spec:
            reviews.append(
                HumanReviewItem(
                    id=f"REV-{review_idx:02d}-SPEC-BOUNDARIES",
                    item="Review unknown analysis boundaries & heuristic control flow",
                    reason="Target contains obfuscated, stripped, or incomplete disassembly sections flagged as tentative inferences.",
                    evidence_status="UNKNOWN_FUNCTIONALITY",
                    recommended_action="Manually validate business logic against functional requirements documentation.",
                )
            )
            review_idx += 1

        # C. Mandatory notice: Scaffolding != Reconstruction
        reviews.append(
            HumanReviewItem(
                id=f"REV-{review_idx:02d}-CLEANROOM-NOTICE",
                item="Independent Implementation Verification",
                reason="Scaffolding and test templates provide structural scaffolding only. They do not constitute a complete, working reimplementation.",
                evidence_status="HEURISTIC_INFERENCE",
                recommended_action="Engineers must implement domain logic in accordance with clean-room guidelines.",
            )
        )

        return tasks, reviews
