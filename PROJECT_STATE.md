# PROJECT_STATE — Nexonic ReForge Studio

_Last updated: 2026-11-10 · v0.5.1 · Publisher: Nexonic Technologies_

## Current milestone
**v0.5.1 — CI Runner Restoration, Cache Enum Deserialization Repair, Scaffold Test Isolation, and Release Pipeline Hardening.**
- macOS Intel Runner: Restored supported `macos-15-intel` runner label across CI, release, and nightly pipelines.
- Cache Engine Enum Deserialization: Fixed `AttributeError: 'str' object has no attribute 'value'` via `Finding.__post_init__`, `Finding.from_dict`, and `AnalysisCache.get_findings`.
- Reconstruction Studio: Standardized Python clean-room scaffold to standard library dependencies (`dataclasses`, `urllib.request`) and injected `pythonpath=src` into `pytest` execution, verified with `test_run_project_tests_live`.
- Rizin Integration: Robust JSON preamble handling and broadened key validation (`info`, `bin`, `core`, `bintype`).
- Release Safety: Strict pre-release gate enforcing verified passing checks on the exact commit before installer compilation.
- Prior Status: `v0.5.0` tag marked unreleased due to CI runner label deprecation and enum deserialization defects discovered during release validation. Superseded by `v0.5.1`.

## Completed (code exists + tests pass)
- Architecture: PySide6/Qt GUI + Python core, SQLite storage, thread-pool background task runner, PyInstaller packaging.
- GUI: 12-section navigation; all 12 pages fully implemented: Dashboard, Import, Analysis Workspace, Application Explorer, Visual UI Explorer, AI Assistant, Reconstruction Studio, Source Workspace, Build & Export, Tool Manager, Activity & Logs, Settings. 0 placeholder pages.
- Safety & Sandboxing: Bounded real-time subprocess streaming reader, strict separation between `extracted/` and clean-room `reconstructed/`, zero host execution of analyzed binaries, DPAPI/Keychain credential encryption, zip slip/bomb protection.
- Reverse-Engineering Adapters: Ghidra 12.2, Detect It Easy, radare2, Rizin, WABT, capa, FLOSS, GoReSym, JADX, ILSpy, pycdc, apktool, binwalk, angr, assetripper, ImHex launcher, Frida device discovery.
- AI & Clean-Room: BYOK provider integration, streaming responses, evidence context synthesis, independent scaffolding, test runner.
- Packaging & Export: Source archives with SHA-256 integrity, CycloneDX SBOM manifests, Markdown/JSON reports, PyInstaller spec (Windows x64 / macOS arm64+x64), Inno Setup installer script, macOS DMG packager.
- CI/CD: Multi-platform GitHub Actions workflows (ubuntu-24.04, macos-15 arm64, macos-15-intel x86_64, windows-2022) with linting, security audits (pip-audit, gitleaks full history), unit tests, integration tests, and release installer generation.

## Test Results
- Total automated tests: 106 tests across unit, GUI, adapters, cache, and export capabilities (94 passed, 12 integration skips when engines not installed on host).
- `ruff check`: All checks clean.
- `pytest`: All passing (100% pass rate).

## Verification & Release Status
- v0.5.1 prepared for PR merge and release tagging after CI passes.
- Windows Inno Setup & macOS DMG packaging validated.
