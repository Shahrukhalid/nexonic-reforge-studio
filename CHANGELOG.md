# Changelog

## [0.11.0] - 2026-11-11
### Added
- **Independent Ground-Truth Benchmarking Engine**:
  - Replaced synthetic finding injection with a genuinely isolated pipeline: reference targets are compiled into real binaries (.pyc, .exe, .class, .dll, native binaries) and analyzed strictly through ReForge's standard analysis engine without any access to ground-truth specifications or original source text.
  - Quantitative measurement of real precision, recall, F1, false positives, false negatives, compiler toolchain versions, optimization levels, and explicit reporting for skipped/unavailable compilers.
  - Added negative regression verification tests confirming accuracy scores drop appropriately when known functions are missing or renamed.
- **Reference-Language Compilation Matrix**:
  - Validated native compilation paths across C, C++ (`reference_engine.cpp`), Go, Rust, Java, C# (`csc` and `dotnet`), Python (`py_compile`), and TypeScript (`node` / `tsc`).
- **Enhanced Clean-Room Technical Isolation Auditor**:
  - Added normalized sequence similarity and sliding-window analysis (`similarity_threshold=0.60`) in `reconstruct.isolation` to detect modified or paraphrased copied content.
  - Enforced symlink validation and directory traversal prevention (`is_relative_to` checks).
  - Explicit legal disclaimer and evidence-based reporting: clearly establishes that technical isolation testing does not constitute legal clean-room certification or copyright non-infringement.
- **Build Output Integrity & Anti-Stale Protections**:
  - Pre-existing file snapshotting in `reconstruct.builder`: strictly isolates newly produced artifacts and ignores stale binaries from earlier builds.
  - Zero-output build rejection: builds returning success with zero produced artifacts are strictly marked as failed.
  - SHA-256 digest validation and manifest verification.
- **Real End-to-End Workflow & Bytecode Analysis**:
  - Direct bytecode analyzers for Python (.pyc via `marshal` and `dis`) and Java (.class via JVM constant pool / method table parser).
  - Full end-to-end reconstruction demonstrated on real compiled bytecode artifacts.

## [0.10.0] - 2026-11-11
### Added
- **Formal Dominator Tree & Advanced Control Flow Graph (CFG) Analysis**:
  - `compute_cfg_dominance`: Computes formal dominator tree ($\text{Dom}(n)$), immediate dominators ($\text{idom}(n)$), Cytron et al. dominance frontiers ($\text{DF}(x)$), natural loops via back-edge identification ($l \to h$ where $h \in \text{Dom}(l)$), and loop bodies.
  - Indirect branch detection (`is_indirect_instruction`) for x86/x64, ARM/AArch64, and MIPS, labeling indirect control transfers and dotted edges in Graphviz DOT and ASCII flow representations.
  - Dead code / unreachable basic block detection (`is_unreachable`, `unreachable_blocks`) with visual badges in graph representations.
- **Ground Truth Reference Benchmarking Suite**:
  - Comprehensive authorized reference fixtures with documented ground-truth contracts for C (`reference_calc.c`), Go (`reference_service.go`), Rust (`reference_lib.rs`), Python (`reference_app.py`), TypeScript (`reference_app.ts`), C# (`ReferenceApp.cs`), and Java (`ReferenceService.java`).
  - Automated compilation and benchmarking engine (`reforge.analysis.benchmark_targets`): compiles reference fixtures using discovered host toolchains (`gcc`, `go`, `rustc`, `javac`, `py_compile`), maps findings to ground-truth specifications, and evaluates precision, recall, and F1 accuracy via `GroundTruthEvaluator`.
- **Clean-Room Isolation Audit Engine**:
  - `verify_cleanroom_isolation` (`reforge.reconstruct.isolation`): scans reconstructed clean-room workspaces against extracted assets to guarantee zero verbatim binary leaks, hash collisions, or proprietary copyright/confidentiality markers.
- **Compiler & Packaging Pipeline Hardening**:
  - Hardened build failure classification in `reforge.reconstruct.builder`: compilation failures strictly set `success=False`, zero out artifacts, and purge stale/partial binaries from distribution folders.
  - Structured test execution summary parser in `reforge.reconstruct.runner`: extracts passed, failed, and skipped counts and execution timings across Pytest, Cargo, .NET, Maven Surefire, and Go test runners.
- **GUI Verification & Visual Documentation**:
  - Verified and captured high-resolution screenshots for all 12 GUI pages in `docs/screenshots/`.

## [0.9.0] - 2026-11-10
### Added
- **Interactive Control Flow Graph (CFG) Visualizer**:
  - `CFGGraph`: Structured graph modeling of function control flow, basic block decomposition, branch classification (conditional true/taken, conditional false/fallthrough, unconditional jump, call, return), cyclomatic complexity ($M = \max(1, E - N + 2)$), and DFS natural loop / back-edge detection.
  - `CFGVisualizerWidget`: Interactive PySide6 component in Application Explorer featuring responsive block cards, colored branch arrows, loop-head badges, text filtering, ASCII/Unicode flow diagram rendering, and Graphviz DOT exporter.
  - Interactive CFG-to-Code navigation: clicking any basic block jumps and centers the code editor at that address.
- **Multi-Engine Decompilation Orchestration**:
  - `DecompilerOrchestrator`: Unified interface aggregating decompiler outputs from Ghidra (NSA), JADX, ILSpy, and clean-room DecompilationSynthesizer.
  - Dynamic engine selection in Application Explorer (`Auto`, `Ghidra`, `JADX`, `ILSpy`, `Synthesizer`) with live switching, provenance banners, and multi-engine similarity diff comparison.
- **Full-Stack Reconstructed Project Toolchains (M9-M10)**:
  - `HostToolchain` discovery engine (`reforge.reconstruct.toolchains`): Probes and detects installed native compiler toolchains across GCC, Clang, MSVC, CMake, Make, Cargo/Rust, Go, Python, .NET SDK (dotnet), JDK/javac/Maven, and Node.js/npm.
  - Expanded native builder (`reforge.reconstruct.builder`): Compiles clean-room projects for C/C++ (via CMake / GCC / Clang / MSVC), C# / .NET (via `dotnet build` / `publish`), Java (via Maven / Gradle / javac / jar), Rust, Go, Python, and TypeScript into standalone desktop binaries and packages with SHA-256 digests and `build_manifest.json`.
  - Expanded test runner (`reforge.reconstruct.runner`): Automates testing for C/C++ (`ctest`), C# (`dotnet test`), Java (`mvn test` / `gradle test`), Rust (`cargo test`), Go (`go test`), and Python (`pytest`).
  - Scaffolding templates (`reforge.reconstruct.scaffold`): Generates independent clean-room projects with multi-module source, unit tests, and build definitions for C/C++, Java, and C# alongside existing Python, TypeScript, Rust, and Go.
  - Build & Export UI integration: Live host compiler discovery status, stack target selection, and one-click compilation.

## [0.8.0] - 2026-11-10
### Added
- **Ground Truth Benchmarking & Accuracy Evaluation Engine**:
  - Legally authorized reference fixtures with documented functions, interfaces, constants, and control flow in C, Java, and C#.
  - `GroundTruthEvaluator`: quantitative measurement of precision, recall, F1 score, true positives, false positives, and missing features.
  - Formal Ground Truth Evaluation Report generation in Markdown and JSON.
- **Genuine Decompiler Integration & Enhanced Control-Flow Analysis**:
  - Differentiates authentic decompiler output (Ghidra, JADX, ILSpy) with `[GENUINE DECOMPILER OUTPUT — EXTRACTED FROM ENGINE]` banners from clean-room heuristic synthesis.
  - Cyclomatic complexity metric calculation ($M = E - N + 2$) across extracted CFG basic blocks and branch edges.
  - Source-to-assembly evidence mapping (`source_asm_map`) linking generated pseudocode lines directly back to binary instructions.
- **Implementation Task Planner & Human Review Checklist**:
  - `TaskPlanner`: synthesizes discrete implementation tasks with categories, dependencies, and acceptance criteria mapped strictly to confirmed findings.
  - Mandatory Human Review Checklist in `ReconstructionStudioPage` (Tab 4 "Tasks & Review") for unknown boundaries and unverified endpoints.
  - Explicit warning enforcement: scaffolding generation is strictly not equivalent to complete application reconstruction.
- **Realistic Behavioral Test Generation**:
  - Eliminated invented default endpoints; tests strictly reflect observed contracts.
  - Cross-platform test suite validation for Python, TypeScript, Rust, Go, and C#.
- **Structural Binary Diffing Engine**:
  - Normalized instruction abstraction (registers, immediates, memory offsets) and CFG topology comparison.
  - Robust matching of renamed symbols and relocated entrypoints with explicit confidence scoring and match reasoning.
  - Accurately flags and reports uncertain structural matches below high-confidence threshold.
- **Release Automation & Provenance Protection**:
  - Enforced tag immutability checks in `scripts/autopilot.py` to prevent accidental tag rewriting and preserve cryptographic release provenance.

## [0.7.0] - 2026-11-10
### Added
- **Advanced Decompilation Synthesizer**:
  - Translates linear disassembly (Capstone) and tool findings into structured, evidence-linked pseudocode (`DecompilationSynthesizer`).
  - Automatic basic block (`CFGBlock`) decomposition, branch target identification, and loop detection.
  - Prominent `[RECONSTRUCTED ANALYSIS - NOT ORIGINAL SOURCE CODE]` banner and exact instruction offset comments.
  - Integrated into the analysis pipeline via `AnalysisOrchestrator` to automatically synthesize decompiled functions.
- **Interactive Binary Diffing Engine**:
  - Deterministic and heuristic multi-level comparison (`BinaryDiffEngine`) of metadata, sections, imports/exports, strings, and functions.
  - Code similarity scoring and unified diff generation for matching functions.
  - Tab 6 ("Binary Diff") in `ApplicationExplorerPage` with target selector, filter controls, summary metrics, and synchronized dual-pane viewer.
  - Markdown and JSON comparison report exporter.
- **Evidence-Based Clean-Room Test Generator**:
  - Multi-language test suite generation (`reforge.reconstruct.tests_gen`) supporting Python, TypeScript, Rust, Go, and C#.
  - Rigorous categorization badges: `[VERIFIED CONTRACT]`, `[BEHAVIORAL MOCK]`, `[MANUAL VALIDATION REQUIRED]`, `[SCAFFOLD INTEGRITY]`.
- **Full Legal License Templates**:
  - Integrated complete, valid legal texts for MIT, Apache-2.0, BSD-3-Clause, and Proprietary licenses into clean-room scaffold generation.
- **Clean-Room Specification Categorization**:
  - Explicit section categorization distinguishing observed facts, inferred behaviors, unverified endpoints, and unknown boundaries.

### Fixed & Hardened
- **Fail-Closed Release Gate**:
  - Enforced strict fail-closed validation on `${{ github.sha }}` in `.github/workflows/release.yml` and `scripts/autopilot.py`: every single required CI check must report conclusion `success` on the exact release commit or the release fails immediately.
  - Eliminated PR-head lookup fallback to ensure release commits are independently verified.
- **Documentation**:
  - Corrected Ghidra requirement to `JDK 25+ required for Ghidra 12.x headless analysis` in `README.md`.

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
