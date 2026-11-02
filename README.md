# Nexonic ReForge Studio

**Publisher:** Nexonic Technologies · **Status:** private development, v0.1.0

A cross-platform desktop workbench (macOS and Windows) for automated, static analysis of software you own or are authorized to analyze, and for clean-room reimplementation of it later.

> ReForge never executes imported applications. Decompiled or inferred output is labelled as such and is never presented as original source code.

## What works today
- Import by drag-and-drop or file picker, with Quick / Standard / Deep scan profiles
- Content-based format identification for 25+ formats, plus hashes and entropy
- Technology fingerprinting (Electron, Flutter, Unity/IL2CPP, Unreal, Godot, React Native, PyInstaller, Go, Rust, Swift/ObjC, .NET, Java, Qt and more)
- Structure analysis of native binaries with LIEF (ELF / PE / Mach-O, including universal binaries)
- Safe extraction of ZIP-family packages, Electron ASAR archives, DMGs (read-only mount) and PKGs
- Strings and network-indicator extraction, with secret redaction
- External tool adapters: radare2 and WABT are verified; DIE, Rizin, capa, FLOSS and GoReSym adapters are written but not yet verified
- Tool Manager showing all 85 catalogued integrations with their live status on your machine
- Markdown and JSON reports, plus a headless CLI

See [PROJECT_STATE.md](PROJECT_STATE.md) for exact status and [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for design.

## Run from source
```bash
python -m venv .venv && source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
reforge                                   # GUI
reforge-cli analyze /path/to/App.dmg --profile standard --report report.md
reforge-cli tools                         # registry status on this machine
pytest -q
```

## Build installers
Push a `v*` tag. The `release` workflow builds `Nexonic_ReForge_Studio_macOS_AppleSilicon.dmg`, `..._macOS_Intel.dmg` and `Nexonic_ReForge_Studio_Windows_x64_Setup.exe` into a draft release. Builds are **unsigned** unless the `MACOS_SIGN_IDENTITY` / `APPLE_NOTARY_PROFILE` secrets are configured.

## Responsible use
For authorized research, interoperability, diagnostics and independent reimplementation only. ReForge contains no features for DRM or licence circumvention, credential theft or unauthorized access.

## Third-party software
See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
