# PROJECT_STATE — Nexonic ReForge Studio

_Last updated: 2026-11-10 · v0.7.0 · Publisher: Nexonic Technologies_

## Published Releases
- **v0.7.0 (Published 2026-11-10T08:58:37Z)**
  - Release URL: https://github.com/Shahrukhalid/nexonic-reforge-studio/releases/tag/v0.7.0
  - Release Commit: `cad6093` (fail-closed release gate verified on commit with all 7 required CI checks passing)
  - Verified Installer Assets:
    - `Nexonic_ReForge_Studio_Windows_x64_Setup.exe` (39,795,605 bytes)
      SHA-256: `478d150a3bd431270ded1dca170e0014ca475798f32b3b0499f5d82ae0e8ce1e`
    - `Nexonic_ReForge_Studio_macOS_AppleSilicon.dmg` (50,093,454 bytes)
      SHA-256: `c9d72c42dac8acfa5949192d46e7e5f890966c0d4e017e15e9b5f1264b5d2f5e`
    - `Nexonic_ReForge_Studio_macOS_Intel.dmg` (54,545,154 bytes)
      SHA-256: `097bc75f3231d1dfed69ba5c5a281cb42115047eea71dd9312ddfbff4ce6b2fd`
    - `SHA256SUMS.txt` (328 bytes — unified manifest verified containing all 3 installer hashes)
- **v0.6.0 (Published 2026-11-10T06:49:27Z)**
  - Release URL: https://github.com/Shahrukhalid/nexonic-reforge-studio/releases/tag/v0.6.0
  - Release Commit: `9a6eb7f` (merged via PR #13)
  - Verified Installer Assets:
    - `Nexonic_ReForge_Studio_Windows_x64_Setup.exe` (39,760,947 bytes / 37.92 MB)
      SHA-256: `d946844672b95251f2f8689c2250e3f8bc66fcb0aa6076c5d61dda9d3e3d06bc`
    - `Nexonic_ReForge_Studio_macOS_AppleSilicon.dmg` (49,199,982 bytes / 46.92 MB)
      SHA-256: `868f65c4bde454a48763d6c380a99b67a2eb40ae2cfbeb206edde3f71d00080c`
    - `Nexonic_ReForge_Studio_macOS_Intel.dmg` (54,680,054 bytes / 52.15 MB)
      SHA-256: `dc2ce52b02e1676c8f5421d8559811135b51f941ab41eef7b43b7235a537547f`
    - `SHA256SUMS.txt` (328 bytes — unified manifest verified containing all 3 installer hashes)
- **v0.5.2 (Published 2026-11-10T06:19:24Z)**
  - Release URL: https://github.com/Shahrukhalid/nexonic-reforge-studio/releases/tag/v0.5.2
  - Release Commit: `a196320` (merged via PR #12)
  - Verified Installer Assets:
    - `Nexonic_ReForge_Studio_Windows_x64_Setup.exe` (39,749,357 bytes / 37.91 MB)
      SHA-256: `714a572677147b5e42e1c2ab547bd2bd1affd19743692346c5ad62d3746850b4`
    - `Nexonic_ReForge_Studio_macOS_AppleSilicon.dmg` (50,008,834 bytes / 47.69 MB)
      SHA-256: `1ac6bd64c21642a90c49b6b64c0d2860f380f835d4b396059ac51ea8d3400a4d`
    - `Nexonic_ReForge_Studio_macOS_Intel.dmg` (54,547,713 bytes / 52.02 MB)
      SHA-256: `a0ccd5fed79af2c0c394f2d5009cd16b159089ad7cec7de80abef7932b9e2620`
    - `SHA256SUMS.txt` (328 bytes — unified manifest verified containing all 3 installer hashes)
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

## Current Milestone: v0.7.0
**v0.7.0 — Advanced Clean-Room Decompilation Synthesis, Diffing & Interactive Binary Navigation.**
- Advanced Decompilation Synthesizer: Heuristic pseudocode generation bridging disassemblers and high-level representations.
- Interactive Binary Diffing: Side-by-side binary and disassembly comparison engine with visual structural diffing.
- End-to-End Clean-Room Pipeline: Automated test generation from discovered binary behavioral profiles.

## Completed (code exists + tests pass)
- Architecture: PySide6/Qt GUI + Python core, SQLite storage, thread-pool background task runner, PyInstaller packaging.
- GUI: 12-section navigation; all 12 pages fully implemented: Dashboard, Import, Analysis Workspace, Application Explorer, Visual UI Explorer, AI Assistant, Reconstruction Studio, Source Workspace, Build & Export, Tool Manager, Activity & Logs, Settings. 0 placeholder pages.
- Safety & Sandboxing: Bounded real-time subprocess streaming reader, strict separation between `extracted/` and clean-room `reconstructed/`, zero host execution of analyzed binaries, DPAPI/Keychain credential encryption, zip slip/bomb protection.
- Reverse-Engineering Adapters: Ghidra 12.2, Detect It Easy, radare2, Rizin, WABT, capa, FLOSS, GoReSym, JADX, ILSpy, pycdc, apktool, binwalk, angr, assetripper, ImHex launcher, Frida device discovery.
- AI & Clean-Room: BYOK provider integration, streaming responses, evidence context synthesis, independent scaffolding, test runner.
- Packaging & Export: Source archives with SHA-256 integrity, CycloneDX SBOM manifests, Markdown/JSON reports, PyInstaller spec (Windows x64 / macOS arm64+x64), Inno Setup installer script, macOS DMG packager.
- CI/CD: Multi-platform GitHub Actions workflows (ubuntu-24.04, macos-15 arm64, macos-15-intel x86_64, windows-2022) with linting, security audits (pip-audit, gitleaks full history), unit tests, integration tests, and release installer generation.
- Release Integrity: SHA-256 checksum aggregation verified across all target platforms with automated release gate and branch protection enforcement.

## Test Results
- Total automated tests: 118 tests across unit, GUI, adapters, cache, synthesizer, binary diffing, test generator, and export capabilities (106 passed, 12 integration skips locally; 112 passed, 6 skips on CI).
- `ruff check`: All checks clean.
- `pytest`: All passing (100% pass rate).

## Verification & Release Status
- v0.7.0 published and verified live on GitHub Releases with complete multi-platform checksum manifest and all 7 CI checks passing on release commit `cad6093`.
