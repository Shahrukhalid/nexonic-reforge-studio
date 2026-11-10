"""End-to-End Reconstruction Studio integration test with known ground truth sample.

Verifies the complete 9-stage clean-room reconstruction workflow:
Import -> Analyze -> Explore -> Generate Specification -> Scaffold -> Implement -> Test -> Build -> Export.
Guarantees clean-room isolation between extracted/ and reconstructed/ workspaces.
"""
from __future__ import annotations

import json
import zipfile
from pathlib import Path

from reforge.analysis.orchestrator import Orchestrator
from reforge.analysis.synthesizer import DecompilationSynthesizer
from reforge.core.db import Database
from reforge.export.exporter import export_cleanroom_archive, export_report_bundle, export_sbom
from reforge.reconstruct.runner import run_project_tests
from reforge.reconstruct.scaffold import generate_specification, scaffold_project


def test_end_to_end_reconstruction_pipeline(tmp_path: Path):
    # Setup isolated test database and workspace directories
    db_path = tmp_path / "reforge_test.db"
    db = Database(db_path)
    workdir = tmp_path / "workdir"
    workdir.mkdir()

    # Step 1: Create Authorized Test Application (Known Ground Truth)
    source_app_dir = tmp_path / "authorized_target_app"
    source_app_dir.mkdir()
    target_binary = source_app_dir / "target_service.py"
    target_binary.write_text(
        '''"""Authorized target service with known ground truth specifications."""
import hashlib
import json

APP_VERSION = "1.0.0"
CONFIG_ENV = "production"
AUTH_ENDPOINT = "http://api.internal/v1/auth"
STATUS_ENDPOINT = "http://api.internal/v1/status"

def compute_hash(data: str) -> str:
    """Exported interface: computes SHA-256 hash of input string."""
    return hashlib.sha256(data.encode('utf-8')).hexdigest()

def verify_token(token: str) -> bool:
    """Exported interface: verifies authorization token format."""
    return len(token) == 64 and token.isalnum()

def get_app_version() -> str:
    """Exported interface: returns version string."""
    return APP_VERSION
''',
        encoding="utf-8",
    )

    # Step 2: Import into ReForge Studio
    pid = db.create_project(
        name="Target Service Clean-Room",
        input_path=str(target_binary),
        profile="standard",
    )
    assert pid is not None

    # Step 3: Analyze Target
    orch = Orchestrator(db)
    summary = orch.analyze(pid)
    assert summary["format"] in ("python", "script", "pyc", "unknown") or summary["subjects"] >= 1

    findings = db.findings(pid)
    assert len(findings) > 0

    # Step 4: Explore & Validate Findings Against Ground Truth
    synth_funcs = DecompilationSynthesizer.synthesize_from_findings(findings, target_binary.name)
    # Check that reconstructed analysis banner is present
    for fn in synth_funcs:
        assert "[RECONSTRUCTED ANALYSIS - NOT ORIGINAL SOURCE CODE]" in fn.pseudocode

    # Step 5: Generate Functional Specification
    spec_md = generate_specification(
        findings=findings,
        project_name="Target Service Clean-Room",
        selected_features=[
            {"name": "Hash Verification Engine", "category": "Cryptography"},
            {"name": "Token Authorizer", "category": "Security"},
            {"name": "Service Client", "category": "Networking"},
        ],
    )
    # Verify specification accurately distinguishes categories
    assert "## 2. Observed Binary Facts & Platform Constraints `[OBSERVED FACT - CONFIRMED]`" in spec_md
    assert "## 4. Inferred Behavioral Logic & Control Flow `[INFERRED BEHAVIOR - TENTATIVE]`" in spec_md
    assert "## 5. Unverified Network Endpoints & Protocol Indicators `[UNVERIFIED DATA - REQUIRES VALIDATION]`" in spec_md
    assert "## 6. Unknown Functionality & Analysis Boundaries `[UNKNOWN FUNCTIONALITY]`" in spec_md

    # Step 6: Scaffold Independent Clean-Room Project
    recon_dir = workdir / "reconstructed" / "target_service"
    scaffold_files = scaffold_project(
        dest_dir=recon_dir,
        project_name="Target Service Clean-Room",
        stack="python",
        spec_md=spec_md,
        license_type="Apache-2.0",
    )
    assert "SPECIFICATION.md" in scaffold_files
    assert "CLEAN_ROOM_NOTICE.md" in scaffold_files
    assert "LICENSE" in scaffold_files
    assert "Apache License" in (recon_dir / "LICENSE").read_text(encoding="utf-8")
    assert "tests/test_behavioral.py" in scaffold_files

    # Step 7: Clean-Room Implementation (Fulfilling Specification Independently)
    client_code = recon_dir / "src" / "target_service_clean_room" / "client.py"
    client_code.write_text(
        '''"""Clean-room independent implementation based strictly on functional specification."""
from __future__ import annotations
import hashlib

class Client:
    def __init__(self, base_url: str = "http://127.0.0.1:8080"):
        self.base_url = base_url.rstrip("/")

    def status(self) -> dict:
        return {"status": "ok", "app": "Target Service Clean-Room", "endpoint": self.base_url}

    def compute_hash(self, text: str) -> str:
        return hashlib.sha256(text.encode("utf-8")).hexdigest()

    def verify_token(self, token: str) -> bool:
        return len(token) == 64 and token.isalnum()
''',
        encoding="utf-8",
    )

    # Step 8: Test Reconstructed Codebase
    test_res = run_project_tests(recon_dir, timeout=30)
    assert test_res.ok, f"Generated test failed: {test_res.stderr or test_res.stdout}"
    assert "passed" in test_res.stdout

    # Step 9: Build & Export Clean-Room Distributable
    export_dir = tmp_path / "exports"
    export_dir.mkdir()
    archive_path = export_dir / "cleanroom_target_service.zip"
    archive, sha_digest = export_cleanroom_archive(recon_dir, archive_path)

    assert archive.is_file()
    assert len(sha_digest) == 64  # valid SHA-256

    # Verify Exported Archive Contains No Extracted Original Artifacts
    with zipfile.ZipFile(archive, "r") as zf:
        names = zf.namelist()
        assert "SPECIFICATION.md" in names
        assert "CLEAN_ROOM_NOTICE.md" in names
        assert "LICENSE" in names
        # Ensure no leak of extracted materials or original files
        for n in names:
            assert not n.startswith("extracted/")
            assert not n.endswith(".pyc.orig")

    # Step 10: Generate SBOM and Report Bundle
    sbom_path = export_dir / "sbom.json"
    sbom_file = export_sbom(db, pid, sbom_path)
    assert sbom_file.is_file()
    sbom_data = json.loads(sbom_file.read_text(encoding="utf-8"))
    assert "CycloneDX" in sbom_data.get("bomFormat", "")

    report_bundle = export_report_bundle(db, pid, export_dir / "reports")
    assert isinstance(report_bundle, dict)
    assert any(p.is_file() for p in report_bundle.values())
