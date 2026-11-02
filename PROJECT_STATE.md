# PROJECT_STATE — Nexonic ReForge Studio

_Last updated: 2026-11-02 · v0.1.0 · Publisher: Nexonic Technologies_

## Current milestone
**M1 Foundation — done. M2 File identification — done. M3 Core tool integration — partial.**

## Completed (code exists + tests pass)
- Architecture: PySide6/Qt GUI + Python core, SQLite, thread-pool tasks, PyInstaller packaging (see docs/ARCHITECTURE.md)
- GUI: 12-section navigation; implemented pages = Dashboard, Import (drag-drop, profiles, cancel), Analysis Workspace (findings tree, filter, detail, re-run, export, delete), Tool Manager (85 entries, live status), Activity & Logs, Settings (theme, limits). Remaining 6 pages show honest "planned" notices.
- Identification: content-based (ELF, PE, Mach-O, fat Mach-O, AppImage, APK, AAB, IPA, JAR/WAR, NuGet, wheel, DEX, WASM, Hermes, ASAR, DMG, XAR/PKG, MSI/OLE, Unity bundle, pyc, gzip/xz/7z/tar, .app bundles); hashes; entropy
- Fingerprinting: ~30 byte markers + ~18 layout rules (Electron, Flutter, Unity/IL2CPP, Unreal, Godot, RN/Hermes, PyInstaller, Go, Rust, Swift/ObjC, Qt, .NET, Java, compilers, UPX, updaters)
- LIEF structure analysis: headers, sections+entropy, libraries, imports/exports, PE signing/.NET CLR/Rich/version info, Mach-O Swift/ObjC/codesign/encryption/build version, fat slices
- Safe extraction: ZIP family + ASAR (native) with traversal, symlink, count, size, ratio (bomb) guards; DMG via `hdiutil -readonly` (macOS) or 7z; PKG via pkgutil/7z; Info.plist metadata/permissions
- Strings: ASCII+UTF-16LE; URLs, domains, IPs, API paths, Windows paths, registry keys, SQL; secret patterns redacted
- Tool adapters (no shell, timeout, output cap, env stripped of *_API_KEY/*_TOKEN): DIE, radare2, Rizin, WABT, capa, FLOSS, GoReSym. **Verified with real output: radare2 (rabin2), WABT (wasm-objdump).**
- Registry: 85 entries, machine-readable JSON, live status per host using the 8 required status labels
- Reports: Markdown + JSON with confidence/provenance; CLI `reforge-cli analyze|tools`
- CI (ubuntu/macOS arm64/macOS x64/Windows) + release workflow (DMG ×2, Inno Setup EXE, draft GitHub release, optional signing/notarization via secrets)

## Latest test results (Linux x86-64, Python 3.13, PySide6 6.12.0, LIEF 1.0.0)
- `pytest`: **28 passed** (incl. offscreen GUI end-to-end, radare2 + WABT integration)
- `ruff check`: clean
- PyInstaller Linux build: built and launched (frozen app starts, logs startup)
- NOT yet run: macOS/Windows CI, DMG/EXE creation (no macOS/Windows host in dev sandbox)

## Known limitations / bugs
- Registry license/maintenance fields are **unverified** (`verification: pending`): GitHub API was unreachable from the dev sandbox. Run `GITHUB_TOKEN=… python scripts/verify_registry.py`.
- Binary AXML (AndroidManifest) not decoded yet — needs Androguard adapter (M4).
- MSI internals, NSIS/Inno installers, PyInstaller archive extraction not implemented (M4).
- DIE, Ghidra headless, JADX, ILSpy adapters not yet verified against real installs.
- Dynamic analysis intentionally disabled (no verified isolation environment).
- Code signing/notarization: workflow hooks only; nothing is signed.

## Next tasks (in order)
1. Push to private GitHub repo; let CI run on macOS/Windows; fix platform failures.
2. Run registry verification with a token; commit results.
3. M3: Ghidra headless adapter (export functions/decompilation JSON via script), DIE verification, Capstone disassembly view.
4. M4: Androguard (APK manifest/permissions/components), PyInstaller extraction, .NET metadata (dnfile) + ilspycmd, JADX, MSI (msitools/7z).
5. Optional tool-pack downloader with pinned URLs + SHA-256.
