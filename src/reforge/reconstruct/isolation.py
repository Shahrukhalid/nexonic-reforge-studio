"""Clean-Room Isolation Audit and Source Tree Integrity Verification Engine.

Provides automated evidence-based auditing of reconstructed source trees against original
extracted application assets. Detects binary leakage, verbatim file duplicates, high-similarity
source copying, directory traversal escapes, and suspicious proprietary markers.

IMPORTANT: This module performs technical integrity checks only. Passing this automated audit
provides empirical evidence of technical separation, but does NOT constitute a legal certification
of clean-room status or copyright non-infringement.
"""
from __future__ import annotations

import difflib
import hashlib
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

# Binary and object extensions that should not exist in clean-room source trees
FORBIDDEN_SOURCE_EXTENSIONS = {
    ".exe", ".dll", ".so", ".dylib", ".bin",
    ".class", ".dex", ".apk", ".o", ".obj",
    ".pyc", ".pyo", ".pyd", ".wasm",
}

# Suspicious proprietary or confidential markers to scan for
SUSPICIOUS_MARKERS = [
    "confidential and proprietary",
    "all rights reserved. strictly prohibited",
    "internal use only",
    "trade secret of",
    "do not distribute",
    "proprietary source code",
]

LEGAL_DISCLAIMER = (
    "Technical isolation scanning checks for binary artifacts, file hash matches, "
    "verbatim text copying, and heuristic text similarity. It provides empirical evidence "
    "of workspace separation, but does NOT constitute a legal certification of clean-room "
    "authorship or copyright non-infringement. Human architectural review remains mandatory."
)


@dataclass
class SuspectedLeak:
    reconstructed_file: str
    extracted_file: str
    similarity_score: float
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class CleanRoomAuditResult:
    is_clean: bool
    requires_human_review: bool
    scanned_files: int
    violation_count: int
    clean_ratio: float
    violations: list[str] = field(default_factory=list)
    suspected_leaks: list[SuspectedLeak] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    disclaimer: str = LEGAL_DISCLAIMER

    def to_dict(self) -> dict[str, Any]:
        return {
            "is_clean": self.is_clean,
            "requires_human_review": self.requires_human_review,
            "scanned_files": self.scanned_files,
            "violation_count": self.violation_count,
            "clean_ratio": self.clean_ratio,
            "violations": self.violations,
            "suspected_leaks": [s.to_dict() for s in self.suspected_leaks],
            "recommendations": self.recommendations,
            "limitations": self.limitations,
            "disclaimer": self.disclaimer,
        }


def _compute_sha256(path: Path) -> str:
    """Compute SHA256 digest of file."""
    h = hashlib.sha256()
    with path.open("rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def _normalize_text(text: str) -> str:
    """Normalize code text by removing comments and whitespace for similarity comparisons."""
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)
    text = re.sub(r"//.*", "", text)
    text = re.sub(r"#.*", "", text)
    return " ".join(text.split())


def verify_cleanroom_isolation(
    extracted_dir: Path | str,
    reconstructed_dir: Path | str,
    allowed_filenames: set[str] | None = None,
    similarity_threshold: float = 0.65,
) -> CleanRoomAuditResult:
    """Audit reconstructed project against extracted application to ensure technical isolation."""
    ext_path = Path(extracted_dir).resolve()
    recon_path = Path(reconstructed_dir).resolve()

    allowed = allowed_filenames or {
        "README.md", "SPECIFICATION.md", "RECONSTRUCTION_PLAN.md",
        "CLEAN_ROOM_NOTICE.md", ".gitignore", "LICENSE",
    }

    violations: list[str] = []
    suspected_leaks: list[SuspectedLeak] = []
    recommendations: list[str] = []
    limitations: list[str] = [
        "Heuristic text similarity checks normalize whitespace and comments; algorithmic equivalence cannot be formally proved.",
        "Automated audit checks file contents and hashes; it cannot verify human developer clean-room procedural isolation.",
    ]

    if not recon_path.exists():
        return CleanRoomAuditResult(
            is_clean=False,
            requires_human_review=True,
            scanned_files=0,
            violation_count=1,
            clean_ratio=0.0,
            violations=[f"Reconstructed directory does not exist: {recon_path}"],
            recommendations=["Scaffold or generate reconstructed workspace before running isolation audit."],
        )

    # 1. Map extracted files: hashes, sizes, and text bodies
    extracted_hashes: dict[str, Path] = {}
    extracted_samples: list[tuple[str, Path]] = []

    if ext_path.exists():
        for f in ext_path.rglob("*"):
            if f.is_file():
                try:
                    fsize = f.stat().st_size
                    if fsize > 64:
                        h = _compute_sha256(f)
                        extracted_hashes[h] = f
                        if fsize < 150_000 and f.suffix.lower() not in FORBIDDEN_SOURCE_EXTENSIONS:
                            raw = f.read_bytes().decode("utf-8", errors="ignore")
                            norm = _normalize_text(raw)
                            if len(norm) > 100:
                                extracted_samples.append((norm, f))
                except Exception:
                    continue

    # 2. Audit reconstructed workspace
    scanned_files = 0
    recon_files: list[Path] = []
    try:
        recon_files = [f for f in recon_path.rglob("*")]
    except Exception as e:
        violations.append(f"Failed to scan reconstructed workspace: {e}")

    for rf in recon_files:
        # Validate path boundaries and symlink security
        try:
            resolved_rf = rf.resolve()
            if not str(resolved_rf).startswith(str(recon_path)):
                violations.append(f"Directory traversal escape detected: {rf} points outside workspace to {resolved_rf}")
                continue
        except Exception as e:
            violations.append(f"Invalid path traversal check on {rf}: {e}")
            continue

        if not rf.is_file():
            continue

        rel = rf.relative_to(recon_path).as_posix()

        # Ignore compiler distribution directories
        if any(part in ("dist", "target", "build", "bin", "obj", "__pycache__") for part in rf.parts):
            continue

        scanned_files += 1

        # Check forbidden binary extensions in source tree
        if rf.suffix.lower() in FORBIDDEN_SOURCE_EXTENSIONS:
            violations.append(
                f"Binary artifact found in source tree: {rel} ({rf.suffix})"
            )
            continue

        if rel in allowed or rf.name in allowed:
            continue

        # Check exact file hash collision with extracted files
        try:
            rsize = rf.stat().st_size
            if rsize > 64:
                rh = _compute_sha256(rf)
                if rh in extracted_hashes:
                    orig = extracted_hashes[rh]
                    violations.append(
                        f"Verbatim file duplicate: {rel} has identical SHA-256 hash to extracted file {orig.name}"
                    )
                    suspected_leaks.append(
                        SuspectedLeak(
                            reconstructed_file=rel,
                            extracted_file=orig.name,
                            similarity_score=1.0,
                            reason="Identical SHA-256 digest to original extracted file",
                        )
                    )
        except Exception:
            pass

        # Check proprietary / confidentiality markers
        try:
            content = rf.read_text(encoding="utf-8", errors="ignore").lower()
            for marker in SUSPICIOUS_MARKERS:
                if marker in content:
                    violations.append(
                        f"Suspicious proprietary marker '{marker}' found in {rel}"
                    )
        except Exception:
            pass

        # Check modified text copying / high-similarity sliding window
        if rf.suffix.lower() not in (".md", ".txt", ".json", ".yaml", ".yml"):
            try:
                r_norm = _normalize_text(rf.read_text(encoding="utf-8", errors="ignore"))
                if len(r_norm) > 100:
                    for ext_norm, ext_file in extracted_samples:
                        # Quick ratio filter before full SequenceMatcher
                        matcher = difflib.SequenceMatcher(None, r_norm, ext_norm)
                        if matcher.quick_ratio() >= similarity_threshold:
                            sim = matcher.ratio()
                            if sim >= similarity_threshold:
                                violations.append(
                                    f"Modified content overlap: {rel} has {sim * 100:.1f}% normalized similarity with extracted file {ext_file.name}"
                                )
                                suspected_leaks.append(
                                    SuspectedLeak(
                                        reconstructed_file=rel,
                                        extracted_file=ext_file.name,
                                        similarity_score=round(sim, 4),
                                        reason=f"Normalized token similarity exceeded threshold ({similarity_threshold * 100:.0f}%)",
                                    )
                                )
                                break
            except Exception:
                pass

    clean_ratio = round((scanned_files - len(violations)) / scanned_files, 4) if scanned_files > 0 else 1.0
    clean_ratio = max(0.0, clean_ratio)
    is_clean = len(violations) == 0
    requires_human_review = not is_clean or len(suspected_leaks) > 0

    if not is_clean:
        recommendations.append("Audit flagged files and remove any copied binaries or verbatim extracted content.")
        recommendations.append("Ensure source code is authored strictly from functional specifications.")
        recommendations.append("Conduct an architectural review of suspected source similarity leaks.")
    else:
        recommendations.append("Technical isolation verified. No binary leaks, hash matches, or high-similarity blocks detected.")
        recommendations.append("Ensure functional tests confirm independent implementation behavior.")

    return CleanRoomAuditResult(
        is_clean=is_clean,
        requires_human_review=requires_human_review,
        scanned_files=scanned_files,
        violation_count=len(violations),
        clean_ratio=clean_ratio,
        violations=violations,
        suspected_leaks=suspected_leaks,
        recommendations=recommendations,
        limitations=limitations,
    )
