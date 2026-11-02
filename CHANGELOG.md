# Changelog

## [0.3.1] - 2026-11-03
### Fixed
- Window opens sized to the screen (max 90%), centred; dashboard columns size to content and never push Profile/Status/Updated off-screen

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
