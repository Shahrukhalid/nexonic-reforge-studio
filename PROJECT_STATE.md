# PROJECT_STATE — Nexonic ReForge Studio

_Last updated: 2026-11-10 · v0.9.0 · Publisher: Nexonic Technologies_

## Release Provenance & Investigation
- **v0.7.0 Release Tag Verification**:
  - Investigation into previous workflow runs confirmed run `42781283931` was blocked at `verify-gate` on commit `5997679` due to incomplete Linux matrix teardown.
  - The permanent release was retagged to verified commit `cad6093` (where all 7 required CI checks passed with `conclusion=success`).
  - Run `42786263594` built all 3 installer artifacts and published release `v0.7.0` with verified 328-byte `SHA256SUMS.txt`.
  - Release tag immutability has been enforced in `scripts/autopilot.py` to prevent accidental tag rewriting permanently.

## Published Releases
- **v0.9.0 (Published 2026-11-10T10:40:34Z)**
  - Release URL: https://github.com/Shahrukhalid/nexonic-reforge-studio/releases/tag/v0.9.0
  - Release Commit: `8b761e4` (merged via PR #16 with all 7 required CI checks passing)
  - Verified Installer Assets:
    - `Nexonic_ReForge_Studio_Windows_x64_Setup.exe` (39,847,008 bytes)
      SHA-256: `12f66496e53bec61ca6e2d3828eaacc7f6f0d3c31dbde3969dd80fb54715dff8`
    - `Nexonic_ReForge_Studio_macOS_AppleSilicon.dmg` (50,123,074 bytes)
      SHA-256: `9052bc0d36f1d5bbc47f7a8e12accf9c47cc77ee5eab695214f535de9c380311`
    - `Nexonic_ReForge_Studio_macOS_Intel.dmg` (54,474,627 bytes)
      SHA-256: `b6ce9e764f12f9d134271bda910309c7133248ced947144c36ffcb1ab5714efa`
    - `SHA256SUMS.txt` (328 bytes — unified manifest verified containing all 3 installer hashes)
- **v0.8.0 (Published 2026-11-10T09:46:26Z)**
  - Release URL: https://github.com/Shahrukhalid/nexonic-reforge-studio/releases/tag/v0.8.0
  - Release Commit: `c26df0f` (merged via PR #15 with all 7 required CI checks passing)
  - Verified Installer Assets:
    - `Nexonic_ReForge_Studio_Windows_x64_Setup.exe` (39,801,687 bytes)
      SHA-256: `1633dc559e21d9c1c71440fb14aac338cc334f3c787a119c02c57a954c19e9e6`
    - `Nexonic_ReForge_Studio_macOS_AppleSilicon.dmg` (50,081,021 bytes)
      SHA-256: `437c1cbcb04e83de4b3a833beb9f4778a43f04194f3503c28b942827b1c04915`
    - `Nexonic_ReForge_Studio_macOS_Intel.dmg` (54,631,090 bytes)
      SHA-256: `0215f7b5ba1b7e78e9faf587dfff52daf2116d3616b2dabea48768f234873958`
    - `SHA256SUMS.txt` (328 bytes — unified manifest verified containing all 3 installer hashes)
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

## Current Milestone: v0.9.0
**v0.9.0 — Multi-Engine Decompilation Orchestration, Interactive Control-Flow Graph (CFG) Visualizer, and Full-Stack Reconstructed Project Toolchains.**
- Interactive Control Flow Graph (CFG) Visualizer: Graph modeling of basic blocks, branch edges (conditional true/false, unconditional, calls), cyclomatic complexity ($M = E - N + 2$), DFS natural loop detection, colored edge rendering, ASCII flow diagram, Graphviz DOT export, and block-to-code navigation.
- Multi-Engine Decompilation Orchestration: Unified interface aggregating and switching between Ghidra (NSA), JADX, ILSpy, and clean-room DecompilationSynthesizer with live engine selector and side-by-side diff comparison.
- Full-Stack Reconstructed Project Toolchains: Host compiler and build toolchain discovery (GCC, Clang, MSVC, CMake, Make, Cargo/Rust, Go, Python, .NET SDK, JDK/javac/Maven, Node.js/npm).
- Multi-Language Scaffolding & Building: End-to-end scaffolding, building, testing, and packaging for C/C++, Java, and C# alongside existing Python, TypeScript, Rust, and Go projects with cryptographic SHA-256 digests and `build_manifest.json`.
- UI Integration: Embedded CFG tab and engine switcher in Application Explorer, plus live host toolchains discovery status and multi-stack compilation in Build & Export.

## Completed (code exists + tests pass)
- Architecture: PySide6/Qt GUI + Python core, SQLite storage, thread-pool background task runner, PyInstaller packaging.
- GUI: 12-section navigation; all 12 pages fully implemented: Dashboard, Import, Analysis Workspace, Application Explorer (Structure, Dependencies, Endpoints, Strings, Call Graph, Binary Diff, CFG Visualizer), Visual UI Explorer, AI Assistant, Reconstruction Studio (4-step wizard with Tasks & Review), Source Workspace, Build & Export, Tool Manager, Activity & Logs, Settings. 0 placeholder pages.
- Safety & Sandboxing: Bounded real-time subprocess streaming reader, strict separation between `extracted/` and clean-room `reconstructed/`, zero host execution of analyzed binaries, DPAPI/Keychain credential encryption, zip slip/bomb protection.
- Reverse-Engineering Adapters: Ghidra 12.2, Detect It Easy, radare2, Rizin, WABT, capa, FLOSS, GoReSym, JADX, ILSpy, pycdc, apktool, binwalk, angr, assetripper, ImHex launcher, Frida device discovery.
- AI & Clean-Room: BYOK provider integration, streaming responses, evidence context synthesis, independent scaffolding, test runner.
- Packaging & Export: Source archives with SHA-256 integrity, CycloneDX SBOM manifests, Markdown/JSON reports, PyInstaller spec (Windows x64 / macOS arm64+x64), Inno Setup installer script, macOS DMG packager.
- CI/CD: Multi-platform GitHub Actions workflows (ubuntu-24.04, macos-15 arm64, macos-15-intel x86_64, windows-2022) with linting, security audits (pip-audit, gitleaks full history), unit tests, integration tests, and release installer generation.
- Release Integrity: SHA-256 checksum aggregation verified across all target platforms with automated release gate, tag immutability, and branch protection enforcement.

## Test Results
- Total automated tests: 133 tests across unit, GUI, adapters, cache, synthesizer, ground truth, tasks, binary diffing, test generator, CFG visualizer, decompiler orchestrator, and toolchains (121 passed, 12 integration skips locally).
- `ruff check`: All checks clean.
- `pytest`: All passing (100% pass rate).

## Verification & Release Status
- v0.9.0 published and verified live on GitHub Releases with complete multi-platform checksum manifest and all 7 CI checks passing on release commit `8b761e4`.
