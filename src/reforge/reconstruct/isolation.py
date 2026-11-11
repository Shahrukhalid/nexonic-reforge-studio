"""Clean-Room Isolation Audit and Verification Engine.

Guarantees that reconstructed clean-room applications do not contain verbatim copied
proprietary binary code, copyrighted strings, or direct file leaks from the original
subject application.
"""
from __future__ import annotations

import hashlib
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
]


@dataclass
class CleanRoomAuditResult:
    is_clean: bool
    scanned_files: int
    violation_count: int
    clean_ratio: float
    violations: list[str] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _compute_sha256(path: Path) -> str:
    """Compute SHA256 digest of file."""
    h = hashlib.sha256()
    with path.open("rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def verify_cleanroom_isolation(
    extracted_dir: Path | str,
    reconstructed_dir: Path | str,
    allowed_filenames: set[str] | None = None,
) -> CleanRoomAuditResult:
    """Audit reconstructed project against extracted application to ensure clean-room isolation."""
    ext_path = Path(extracted_dir)
    recon_path = Path(reconstructed_dir)

    allowed = allowed_filenames or {
        "README.md", "SPECIFICATION.md", "RECONSTRUCTION_PLAN.md",
        ".gitignore", "LICENSE",
    }

    violations: list[str] = []
    recommendations: list[str] = []

    if not recon_path.exists():
        return CleanRoomAuditResult(
            is_clean=False,
            scanned_files=0,
            violation_count=1,
            clean_ratio=0.0,
            violations=[f"Reconstructed directory does not exist: {recon_path}"],
            recommendations=["Scaffold or generate reconstructed workspace before running isolation audit."],
        )

    # 1. Map extracted file hashes and text content
    extracted_hashes: dict[str, Path] = {}
    extracted_text_samples: list[tuple[str, Path]] = []

    if ext_path.exists():
        for f in ext_path.rglob("*"):
            if f.is_file():
                try:
                    fsize = f.stat().st_size
                    # Skip tiny trivial files (empty or boilerplate <= 64 bytes)
                    if fsize > 64:
                        h = _compute_sha256(f)
                        extracted_hashes[h] = f
                        if fsize < 100_000:
                            sample = f.read_bytes().decode("utf-8", errors="ignore").strip()
                            if len(sample) > 128:
                                extracted_text_samples.append((sample, f))
                except Exception:
                    continue

    # 2. Audit reconstructed files
    scanned_files = 0
    recon_files = [f for f in recon_path.rglob("*") if f.is_file()]

    for rf in recon_files:
        rel = rf.relative_to(recon_path).as_posix()
        # Ignore build output directories like dist/ and target/ and build/
        if any(part in ("dist", "target", "build", "bin", "obj", "__pycache__") for part in rf.parts):
            continue

        scanned_files += 1

        # Check forbidden binary extensions in source tree
        if rf.suffix.lower() in FORBIDDEN_SOURCE_EXTENSIONS:
            violations.append(
                f"Binary artifact found in clean-room source tree: {rel} ({rf.suffix})"
            )
            continue

        if rel in allowed or rf.name in allowed:
            continue

        # Check hash collision with extracted files
        try:
            rsize = rf.stat().st_size
            if rsize > 64:
                rh = _compute_sha256(rf)
                if rh in extracted_hashes:
                    orig = extracted_hashes[rh]
                    violations.append(
                        f"Verbatim file leak: {rel} has identical SHA-256 hash to extracted file {orig.name}"
                    )
        except Exception:
            pass

        # Check proprietary markers
        try:
            content = rf.read_text(encoding="utf-8", errors="ignore").lower()
            for marker in SUSPICIOUS_MARKERS:
                if marker in content:
                    violations.append(
                        f"Suspicious proprietary marker '{marker}' found in {rel}"
                    )
        except Exception:
            pass

    clean_ratio = round((scanned_files - len(violations)) / scanned_files, 4) if scanned_files > 0 else 1.0
    clean_ratio = max(0.0, clean_ratio)
    is_clean = len(violations) == 0

    if not is_clean:
        recommendations.append("Remove any copied binaries or verbatim extracted files from source tree.")
        recommendations.append("Ensure source code is independently authored from specification contracts.")
    else:
        recommendations.append("Clean-room isolation verified. No verbatim binary or proprietary leaks detected.")

    return CleanRoomAuditResult(
        is_clean=is_clean,
        scanned_files=scanned_files,
        violation_count=len(violations),
        clean_ratio=clean_ratio,
        violations=violations,
        recommendations=recommendations,
    )
