# Changelog

## [0.2.0] - 2026-11-02
### Added
- Capstone disassembly (x86, x86-64, ARM, ARM64) of entry points and exported functions, per universal-binary slice
- Ghidra 12.2 headless adapter with `ReForgeExport.java`: functions, signatures, call graph, decompilation of the 25 largest functions (labelled as decompiled, never as source)
- Verified tool-pack installer (`reforge-cli toolpack install ghidra`): pinned HTTPS URL, SHA-256 checked before extraction, safe extraction limits
- CI integration job running real Ghidra 12.2 and Detect It Easy 3.21 (both SHA-256 pinned)
- Registry: 54/85 entries verified against the GitHub API (licence, archived, last push); 6 flagged unmaintained
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
