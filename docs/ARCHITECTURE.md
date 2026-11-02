# Architecture decision record

## Decision: PySide6 (Qt 6) desktop shell + Python core

| Criterion | PySide6/Qt | Tauri 2 (Rust + WebView) |
|---|---|---|
| Python RE ecosystem (LIEF, angr, capstone, androguard, capa, FLOSS, frida) | In-process | Needs a sidecar Python runtime + IPC |
| Native look / HiDPI / drag-drop | Native widgets | WebView |
| Packaging | PyInstaller → .app/DMG, Inno Setup EXE | Small binaries, but sidecar Python must still be bundled |
| Licence | PySide6 LGPLv3 (dynamic linking, permitted for closed distribution) | MIT/Apache |
| Maintainability | One language for UI + core | Two stacks |

Most of the analysis engines are Python libraries, so Qt avoids an IPC layer and a second runtime. Rust/C++ stay available as CLI tools or native wheels.

## Layers
```
src/reforge/
  core/        paths, db (SQLite + on-disk artifacts), findings schema, safety (limits, path guard, tool runner), tasks
  analysis/    identify → extract → fingerprint → binary (LIEF) → strings → tool adapters → report
  tools/       registry.json (85), registry.py (live status), adapters/ (CLI wrappers → Findings)
  ui/          main_window (nav + AppContext + Qt signal bridge), pages/, theme (light/dark QSS)
  cli.py       headless entry point (same orchestrator)
```

## Key rules
- **Targets are never executed.** Only registry analysis tools run, as argv lists (no shell), under a timeout and output cap, with secret-like env vars removed.
- All findings carry `confidence` (confirmed / strongly_inferred / tentative / unknown) and `provenance` (extracted_data / parsed_structure / inferred_behavior / decompiled / generated).
- Originals are read-only. Extraction goes to the per-project workdir and is guarded against traversal, symlinks, file-count, size and compression-ratio bombs.
- Tool status is always computed live on the host. The catalog never claims a tool is installed.
- Database stores metadata. Large extracted files live on disk under the project workdir.

## Platform adapters
DMG: `hdiutil attach -readonly -nobrowse` (macOS) → 7-Zip fallback. PKG: `pkgutil --expand` → 7-Zip. Windows-only tools (x64dbg, dnSpyEx, PE-sieve, FModel) are reported as *Unsupported on current operating system* on macOS/Linux.
