# PROJECT_STATE — Nexonic ReForge Studio

_Last updated: 2026-11-02 · v0.2.0 · Publisher: Nexonic Technologies_

## Current milestone
**M1 — done (verified on real Mac). M2 — done. M3 Core tool integration — done (CI run 41469838668: real Ghidra 12.2 + DIE 3.21 + radare2 + WABT all PASSED).** Next: M4.

## Completed (code exists + tests pass)
- Architecture: PySide6/Qt GUI + Python core, SQLite, thread-pool tasks, PyInstaller packaging (see docs/ARCHITECTURE.md)
- GUI: 12-section navigation; implemented pages = Dashboard, Import (drag-drop, profiles, cancel), Analysis Workspace (findings tree, filter, detail, re-run, export, delete), Tool Manager (85 entries, live status), Activity & Logs, Settings (theme, limits). Remaining 6 pages show honest "planned" notices.
- Identification: content-based (ELF, PE, Mach-O, fat Mach-O, AppImage, APK, AAB, IPA, JAR/WAR, NuGet, wheel, DEX, WASM, Hermes, ASAR, DMG, XAR/PKG, MSI/OLE, Unity bundle, pyc, gzip/xz/7z/tar, .app bundles); hashes; entropy
- Fingerprinting: ~30 byte markers + ~18 layout rules (Electron, Flutter, Unity/IL2CPP, Unreal, Godot, RN/Hermes, PyInstaller, Go, Rust, Swift/ObjC, Qt, .NET, Java, compilers, UPX, updaters)
- LIEF structure analysis: headers, sections+entropy, libraries, imports/exports, PE signing/.NET CLR/Rich/version info, Mach-O Swift/ObjC/codesign/encryption/build version, fat slices
- Safe extraction: ZIP family + ASAR (native) with traversal, symlink, count, size, ratio (bomb) guards; DMG via `hdiutil -readonly` (macOS) or 7z; PKG via pkgutil/7z; Info.plist metadata/permissions
- Strings: ASCII+UTF-16LE; URLs, domains, IPs, API paths, Windows paths, registry keys, SQL; secret patterns redacted
- Tool adapters (no shell, timeout, output cap, env stripped of *_API_KEY/*_TOKEN): DIE, radare2, Rizin, WABT, capa, FLOSS, GoReSym. **Verified with real output in CI: Ghidra 12.2 headless (functions + decompilation), Detect It Easy 3.21, radare2, WABT.**
- Registry: 85 entries, machine-readable JSON, live status per host using the 8 required status labels. **54 verified** via GitHub API (2026-11-02); 31 pending (API rate limit). Unmaintained: DerekSelander LLDB, class-dump, dex2jar, Il2CppDumper, UEViewer, Unity-game-hacking
- v0.2.0: Capstone disassembly; Ghidra headless adapter + ReForgeExport.java; SHA-256-pinned tool-pack installer (Ghidra 12.2); grouped findings tree; numeric sort
- Reports: Markdown + JSON with confidence/provenance; CLI `reforge-cli analyze|tools`
- CI (ubuntu/macOS arm64/macOS x64/Windows) + release workflow (DMG ×2, Inno Setup EXE, draft GitHub release, optional signing/notarization via secrets)

## Latest test results (Linux x86-64, Python 3.13, PySide6 6.12.0, LIEF 1.0.0)
- `pytest` (v0.2.0, sandbox): **38 passed, 2 skipped** (Ghidra/DIE not installable in sandbox → CI integration job)
- `ruff check`: clean
- PyInstaller Linux build: built and launched (frozen app starts, logs startup)
- **GitHub CI run #2 (46ee4cb): SUCCESS** on ubuntu-24.04, macos-14 (arm64), macos-15-intel, windows-2022 + audit (pip-audit, gitleaks)
- **CI 7fd6ce0: ALL GREEN** — 4 OS test jobs, audit (pip-audit caught capstone PYSEC-2026-3544 → fixed 5.0.8), integration 4/4 passed
- **Release workflow v0.1.0: SUCCESS** — 3 builds (macOS AppleSilicon DMG, macOS Intel DMG, Windows Setup EXE) + draft GitHub release. Unsigned. Not yet install-tested by a human.

## Known limitations / bugs
- 31 registry entries still `verification: pending` (anonymous GitHub API limit). Re-run via browser helper + `scripts/apply_verification.py`, or `GITHUB_TOKEN=… python scripts/verify_registry.py`.
- Binary AXML (AndroidManifest) not decoded yet — needs Androguard adapter (M4).
- MSI internals, NSIS/Inno installers, PyInstaller archive extraction not implemented (M4).
- JADX, ILSpy, capa, FLOSS, GoReSym, Rizin adapters not yet verified against real installs.
- Tool packs: only Ghidra so far; no GUI install button yet (CLI only). Ghidra needs JDK 21 on the user's machine.
- Dynamic analysis intentionally disabled (no verified isolation environment).
- Code signing/notarization: workflow hooks only; nothing is signed.

## Next tasks (in order)
1. Tag v0.2.0 → release build; install-test on Mac (Deep scan needs JDK 21 + `reforge-cli toolpack install ghidra`).
2. Verify remaining 31 registry entries.
3. Tool Manager: "Install" button for tool packs (+ JDK check); DIE pack for macOS/Windows.
4. M4: Androguard (APK manifest/permissions/components), PyInstaller extraction, .NET metadata (dnfile) + ilspycmd, JADX, MSI (msitools/7z).
5. Optional tool-pack downloader with pinned URLs + SHA-256.
