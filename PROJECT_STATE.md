# PROJECT_STATE — Nexonic ReForge Studio

_Last updated: 2026-11-10 · v0.5.2-dev · Publisher: Nexonic Technologies_

## Published Releases
- **v0.5.1 (Published 2026-11-10T05:47:12Z)**
  - Release URL: https://github.com/Shahrukhalid/nexonic-reforge-studio/releases/tag/v0.5.1
  - Release Commit: `6fa5595` (merged via PR #11)
  - Verified Installer Assets:
    - `Nexonic_ReForge_Studio_Windows_x64_Setup.exe` (39,754,838 bytes / 37.91 MB)
      SHA-256: `e1159427795d0cc0f2286d5c86d7c562ca87a64994e0da032f8af81974968bbf`
    - `Nexonic_ReForge_Studio_macOS_AppleSilicon.dmg` (50,008,011 bytes / 47.69 MB)
      SHA-256: `4146fcad1c24930328682cc98e67fee1b3e32d47507887eabafb07709c7acd30`
    - `Nexonic_ReForge_Studio_macOS_Intel.dmg` (54,549,742 bytes / 52.02 MB)
      SHA-256: `e9164eac7f817311a3ebf5f86e9908a9fdc2a6bfb10dcb4f7868886078814508`
    - `SHA256SUMS.txt` (112 bytes)

## Current Milestone: v0.5.2
**v0.5.2 — Automation Hardening, Checksum Aggregation, Auto-Merge Race Resolution, and Branch Protection Enforcement.**
- Release Checksum Aggregation: Solved artifact overwriting during download by naming per-platform manifests (`dist/SHA256SUMS-${{ matrix.label }}.txt`), aggregating all entries into a unified `SHA256SUMS.txt`, verifying that all 3 installer hashes exist and match disk files, and failing release if any are missing.
- Auto-Merge Race Condition: Made auto-merge idempotent with concurrency grouping (`auto-merge-${{ github.event.pull_request.number }}` with `cancel-in-progress: true`) and graceful error handling on duplicate triggers.
- Branch Protection: Enforced all 7 required CI checks (`test (ubuntu-24.04)`, `test (macos-15)`, `test (macos-15-intel)`, `test (windows-2022)`, `audit`, `integration`, `integration-macos`) on `main` via GitHub branch protection rules.
- Autopilot Controller: Added `check-ci` and `tag` subcommands with automated PR-to-squash commit check resolution.

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
- v0.5.1 published and verified live on GitHub Releases.
- v0.5.2 automation hardening PR undergoing CI validation.
