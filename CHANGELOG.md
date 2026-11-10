# Changelog

## [0.6.0] - 2026-11-10
### Added
- **Interactive Decompilation & Disassembly Viewer**:
  - Assembly syntax highlighting (`CodeHighlighter`) for x86/x64 and ARM/ARM64 mnemonics, registers, memory addresses, and comments.
  - JSON syntax highlighting for keys, strings, numbers, and boolean literals.
  - In-line Find Bar (`Ctrl+F`, `Esc`) in Analysis Workspace with previous/next navigation, wrap-around search, and live match counter.
- **Deep Call Graph & Cross-Reference Explorer**:
  - Linear disassembly branch/call instruction parser (`call`, `jmp`, `bl`, `bx`, etc.) constructing caller -> callee cross-references even in headless environments.
  - Bidirectional symbol resolution against imported and exported functions.
- **Reconstruction Studio Multi-Module Scaffolding & Spec Generator**:
  - Automated `generate_specification` synthesizing binary architecture, external libraries, API routes, and indicator schemas into clean-room `SPECIFICATION.md`.
  - Multi-module clean-room scaffolding (`core.py`, `models.py`, `client.py`, `cli.py`, `tests/`) for Python, TypeScript, Rust, and Go.

## [0.5.2] - 2026-11-10
### Fixed & Hardened
- **Release Checksum Aggregation**:
  - Resolved artifact overwriting during download by producing unique matrix checksum files (`dist/SHA256SUMS-${{ matrix.label }}.txt`).
  - Added multi-platform checksum aggregation and strict verification in `publish` job: parses all hashes, verifies that `Windows_x64_Setup.exe`, `macOS_AppleSilicon.dmg`, and `macOS_Intel.dmg` are present, and validates that every file on disk matches its SHA-256 digest before publication.
- **Auto-Merge Race Condition Resolution**:
  - Configured concurrency control (`auto-merge-${{ github.event.pull_request.number }}` with `cancel-in-progress: true`) preventing concurrent auto-merge workflows from clashing.
  - Made auto-merge step idempotent by catching and safely inspecting already-merged/in-progress PR states.
- **Release CI Gate Enforcement**:
  - Implemented `verify-gate` job in `release.yml` and `check-ci` / `tag` commands in `scripts/autopilot.py` to ensure all 7 required checks (`test (ubuntu-24.04)`, `test (macos-15)`, `test (macos-15-intel)`, `test (windows-2022)`, `audit`, `integration`, `integration-macos`) are verified passing before release builds proceed.
  - Enabled branch protection rules on `main` to prevent merging PRs unless all 7 required CI checks succeed.

## [0.5.1] - 2026-11-10
### Fixed
- **Analysis Cache Enum Deserialization**:
  - Added `Finding.__post_init__` and `Finding.from_dict` ensuring cached finding strings are converted into proper `Confidence` and `Provenance` enums.
  - Resolved `AttributeError: 'str' object has no attribute 'value'` across Linux/macOS runs in `AnalysisOrchestrator` and `Database.add_findings`.
  - Added `AnalysisCache.get_findings` and cold/warm cache regression tests (`test_cold_and_warm_cache_findings_enums`).
- **Reconstruction Studio Scaffolding & Live Runner**:
  - Removed third-party dependencies (`requests`, `pydantic`) from generated clean-room Python scaffold skeleton; replaced with standard library `dataclasses` and `urllib.request`.
  - Configured test runner to inject `pythonpath=src` into `pytest` invocation, allowing scaffolded projects to execute test suites live out of the box (`test_run_project_tests_live`).
- **macOS Intel Runner Restoration**:
  - Restored official supported `macos-15-intel` runner label across CI, release, and nightly workflows.
- **Rizin Integration & Test Diagnostics**:
  - Enhanced adapter JSON output parser (`_json_or_text`) to strip banner and diagnostic preamble text before parsing tool JSON.
  - Updated Rizin test assertion to accept standard Rizin `info`, `bin`, and `core` JSON structures.
  - Updated macOS integration job to require `test_rizin_integration` explicitly while allowing optional external tools to be reported cleanly.
- **Safe Release Pipeline**:
  - Added release gate verification preventing installer generation or publication unless CI quality gates for the exact commit have succeeded.

## [0.5.0] - 2026-11-10 [UNRELEASED - CI GATES FAILED]
### Added
- **Persistent Analysis Cache Engine (`reforge.analysis.cache.AnalysisCache`)**:
  - SHA-256 keyed caching of tool analysis and decompiler findings on disk.
- **Application Explorer Enhancements**:
  - Interactive "Copy Code" action copying disassembled and decompiled snippets to system clipboard.
  - "Save Code to File…" action saving code snippets directly to user-specified paths.
- **Visual UI Explorer Enhancements**:
  - Added "Export Asset…" button and file exporter for saving selected image assets, layouts, and embedded UI resources.
- **AI Assistant Enhancements**:
  - Live prompt token estimator (`lbl_token_est`) providing pre-dispatch token budget visibility.
- **Reconstruction Studio & Native Compiler Bundling**:
  - Standalone distribution archive packaging (`<app>_dist.zip`) with automated `.sha256` integrity manifest generation upon clean-room build completion.
### Fixed & Optimized
- **GitHub Workflows Self-Repair & Consolidation**:
  - Corrected macOS Intel runner label to `macos-13` across CI and release workflows.
  - Upgraded all GitHub Actions to verified major releases (`actions/checkout@v7`, `setup-python@v7`, `upload-artifact@v7`, `download-artifact@v8`, `setup-java@v6`, `action-gh-release@v3`, `gitleaks/gitleaks-action@v3`).
  - Added Dependabot grouping (`groups`) in `.github/dependabot.yml` to eliminate individual PR spam and race conditions.
  - Created missing repository labels (`dependencies`, `auto-merge`) on GitHub.
  - Enabled native GitHub repository auto-merge (`allow_auto_merge=True`) and automatic branch deletion (`delete_branch_on_merge=True`).
  - Verified and upgraded Capstone from 5.0.8 to `capstone==5.0.9`.
  - Replaced placeholder `README.md` with complete, professional public documentation.

## [0.4.0] - 2026-11-10
### Added
- **M5 Reverse-Engineering Tool Ecosystem**:
  - Full verification of all 85 tools in the tool registry via live GitHub API verification (verified=85, pending=0, failed=0).
  - Live version detection (`_bin_version`) and path probing for host reverse-engineering binaries.
  - Native adapters for `apktool` (manifest & resource decoding), `binwalk` (firmware signature carving), `angr` (static CFG analysis), and `assetripper` (Unity asset packages).
  - Pinned SHA-256 tool packs for JADX 1.5.0 and WABT 1.0.42 with multi-platform resolution (Linux, macOS arm64/x64, Windows) and tar.gz/zip safe extraction.
  - Integrated PR #1: Rizin integration, ImHex external launcher, and safe Frida bridge (device listing only; dynamic instrumentation strictly disabled).
  - Integrated PR #2: Standardized pull request and issue templates, CONTRIBUTING.md guidelines.
  - Interactive Tool Manager with multi-pack installation, status indicators, build decompiler action, and Third-Party Notices dialog.
- **M6 Application Explorer & Visual UI Explorer**:
  - `ApplicationExplorerPage`: Hierarchical module/class/section browser, imported libraries & symbols, network endpoints, embedded strings & config, call graphs, and monospace syntax-highlighted code viewer with confidence & provenance tags.
  - `VisualUIExplorerPage`: UI resource catalog (AXML layouts, HTML/CSS, XAML, Qt resources, graphics), interactive image preview with dimension & zoom controls, reference screenshot import, and UI component-to-evidence mapping table.
  - `CodeHighlighter`: Cross-platform syntax highlighting supporting C/C++, Java, Python, JavaScript/TypeScript, C#, Rust, Go, XML/HTML, and JSON.
- **M7 AI Assistant (BYOK)**:
  - `AIAssistantPage`: Bring Your Own Key AI assistant supporting OpenRouter, OpenAI, Anthropic, Gemini, and Local (Ollama/OpenAI-compatible) models.
  - OS-protected credential storage leveraging Windows DPAPI (`CryptProtectData`) and macOS Keychain.
  - Project-aware context compiler enforcing strict clean-room boundaries, anti-hallucination rules, and evidence provenance.
  - Streaming conversational assistant with responsive token cancellation and mandatory explicit user consent checkbox before sending project context.
- **M8 Reconstruction Studio & Source Code Workspace**:
  - `ReconstructionStudioPage`: 3-step clean-room reconstruction wizard (Feature Discovery & Selection -> Functional Specification Generation -> Architecture Scaffolding).
  - `scaffold`: Clean-room project scaffolding for Python, TypeScript, Rust, Go, and C# into isolated `reconstructed/` directories with `SPECIFICATION.md` and `CLEAN_ROOM_NOTICE.md`.
  - `SourceWorkspacePage`: Multi-tab source editor with syntax highlighting, clean-room file explorer, diff viewer against disk, and integrated test/build console supporting `pytest`, `npm test`, `cargo test`, and `go test`.
- **M9-M10 Build, Export & Packaging Pipeline**:
  - `BuildExportPage`: Centralized export hub replacing final planned placeholder, achieving 100% genuine functional implementation across all 12 navigation pages.
  - Clean-room source archive exporter producing `.zip` and `.tar.gz` packages accompanied by `.sha256` integrity manifests.
  - CycloneDX-compatible Software Bill of Materials (SBOM) JSON generation from discovered libraries, npm packages, and .NET assemblies.
  - Automated report bundle export packaging Markdown, JSON, and SBOM analysis outputs.
  - Installer & packaging configuration validator for PyInstaller spec, Inno Setup definition, and macOS DMG builder.
### Security
- Hardened cross-platform subprocess execution with streaming threaded reader enforcing real-time output bounds and terminating runaway processes immediately.
- Enforced strict clean-room isolation between extracted binaries and reconstructed source code.
- Dynamic analysis remains disabled pending verified isolated sandbox environment.
- Gitleaks history scanning and CI security audit gates updated to full git history checkout.
### Fixed
- Fixed GitHub Actions runner deprecation by migrating from `macos-14` to `macos-15` (Apple Silicon).
- Fixed cross-platform test subprocess execution on Windows without depending on Unix-only shell commands.

## [0.3.0] - 2026-11-02
### Added
- Android: native binary-XML (AXML) manifest decoder - package, versions, SDK levels, permissions,
  components with export status, manifest risk notes, readable XML; DEX header + class listing
- PyInstaller: static CArchive reader/extractor; entry scripts written as valid .pyc for decompilers
- .NET: assembly identity, references, types/methods, P/Invoke imports, resources (dnfile)
- MSI: native Windows Installer reader (summary info + Property/File/Component/Registry/
  CustomAction/ServiceInstall... tables) - no msitools needed; verified against msiinfo
- Adapters: JADX (APK/DEX/JAR), ILSpy/ilspycmd (.NET), pycdc (.pyc) - deep/standard profiles
- Tool Manager: Ghidra install + "Build decompiler" buttons with JDK/decompiler status
- Import: re-analysing an identical file offers to re-run the existing project
- Real test fixtures built with aapt/dx (APK) and wixl (MSI); PyInstaller + .NET samples built/fetched in tests
### Changed
- Releases are published as private pre-releases (draft releases are not visible to `gh release download`)
- Dashboard columns size to content
### Fixed (field test on Apple Silicon)
- TLS via certifi, JDK 25 discovery for Ghidra 12.2, universal-binary thinning, Ghidra native build via gradlew


## [0.2.0] - 2026-11-02
### Added
- Capstone disassembly (x86, x86-64, ARM, ARM64) of entry points and exported functions, per universal-binary slice
- Ghidra 12.2 headless adapter with `ReForgeExport.java`: functions, signatures, call graph, decompilation of the 25 largest functions (labelled as decompiled, never as source)
- Verified tool-pack installer (`reforge-cli toolpack install ghidra`): pinned HTTPS URL, SHA-256 checked before extraction, safe extraction limits
- CI integration job running real Ghidra 12.2 and Detect It Easy 3.21 (both SHA-256 pinned)
- Registry: 54/85 entries verified against the GitHub API (licence, archived, last push); 6 flagged unmaintained
### Security
- capstone 5.0.6 -> 5.0.8 (PYSEC-2026-3544), caught by the CI pip-audit gate
### Fixed
- Tool Manager `#` column now sorts numerically
- Analysis Workspace groups findings by stage, then by file; subjects show file names with full path on hover
- Disassembly and decompiled code render as monospace text instead of JSON

## [0.1.0] - 2026-11-02
### Added
- PySide6 desktop shell with 12-section navigation, light/dark themes
- SQLite project store, background task manager, rotating log
- Content-based identification, fingerprinting, LIEF binary analysis, strings/network indicators
- Safe ZIP/ASAR/DMG/PKG extraction with archive-bomb and traversal guards
- 85-entry tool registry with live status; radare2, WABT, DIE, Rizin, capa, FLOSS, GoReSym adapters
- Markdown/JSON reports, `reforge-cli`
- CI (Linux/macOS/Windows) and release workflows (DMG, Inno Setup EXE)
