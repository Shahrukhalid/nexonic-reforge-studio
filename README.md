# Nexonic ReForge Studio

[![CI](https://github.com/Shahrukhalid/nexonic-reforge-studio/actions/workflows/ci.yml/badge.svg)](https://github.com/Shahrukhalid/nexonic-reforge-studio/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/Shahrukhalid/nexonic-reforge-studio?include_prereleases)](https://github.com/Shahrukhalid/nexonic-reforge-studio/releases)
[![Python 3.12](https://img.shields.io/badge/python-3.12-blue.svg)](https://www.python.org/downloads/)
[![Qt 6 / PySide6](https://img.shields.io/badge/Qt-6.12-green.svg)](https://www.qt.io/)
[![License](https://img.shields.io/badge/license-Proprietary-red.svg)](#license)

**Nexonic ReForge Studio** is an advanced desktop reverse-engineering workbench and clean-room software reconstruction studio. It integrates industry-standard static analysis engines, disassemblers, decompilers, visual asset extractors, and clean-room specification builders into a unified desktop environment.

---

## Key Capabilities

- **Multi-Format Binary Inspection:** Deep header parsing, section analysis, symbol resolution, and security mitigations (ASLR, DEP, SafeSEH, Control Flow Guard) for PE, ELF, Mach-O, .NET assemblies (`dnfile`), and Compound File Binary formats (`olefile`) powered by [LIEF](https://github.com/lief-project/LIEF).
- **Integrated Disassembly & Decompilation:** Native entry-point and exported function disassembly using [Capstone Engine](https://www.capstone-engine.org/) (x86, x64, ARM, ARM64), verified [Ghidra](https://ghidra-sre.org/) headless orchestration, [Rizin](https://rizin.re/), and [Detect It Easy (DIE)](https://github.com/horsicq/DIE-engine) integration.
- **Application Explorer:** Fast navigation through binary metadata, imported/exported APIs, suspicious strings, sections, and decompiled pseudo-code with direct clipboard and export actions.
- **Visual UI Explorer:** Extraction and inspection of embedded graphic resources, icons, dialogs, and string tables from imported binaries, with one-click asset export.
- **AI-Assisted Architectural Summarization:** Secure, opt-in AI assistant supporting Bring-Your-Own-Key (BYOK) configurations (Anthropic, OpenAI, Local Ollama) with real-time prompt token estimation for analyzing complex decompiled functions and generating clean-room functional specifications.
- **Clean-Room Reconstruction Studio:** Structured workflow for translating reverse-engineering findings into functional specifications, modular project structures, and verifiable test plans without contaminating clean-room boundaries.
- **Source Code Workspace & Native Compiler:** Built-in code editor, automated CMake / C++ / Python project compilation, and automated packaging of standalone distributable archives (`.zip`) with SHA-256 verification manifests.
- **Tool Manager:** Integrated status monitoring, SHA-256 verified download, safe extraction, and dependency checking for 85+ reverse-engineering tools.
- **Persistent Analysis Cache:** SHA-256 keyed caching engine preventing redundant disassemblies and decompiler passes across sessions.

---

## System Requirements & Supported Platforms

| Platform | Architecture | Status |
|---|---|---|
| **Windows** | x86_64 (Windows 10, 11, Windows Server 2022+) | Supported (Setup Installer & Portable) |
| **macOS** | Apple Silicon (arm64, macOS 14 Sonoma, macOS 15 Sequoia) | Supported (Disk Image DMG) |
| **macOS** | Intel (x86_64, macOS 13 Ventura+) | Supported (Disk Image DMG) |
| **Linux** | x86_64 (Ubuntu 24.04 LTS, Debian 12+) | Core CLI & Test Pipeline Supported |

### Prerequisites
- Python 3.11 or Python 3.12
- Git
- For Ghidra analysis: Java Development Kit (JDK 25+ required for Ghidra 12.x headless analysis, e.g. OpenJDK 25 EA or Adoptium / Temurin 25+)
- For native build tasks: CMake 3.25+ and platform C++ compiler (MSVC, Clang, or GCC)

---

## Installation & Development Setup

### 1. Clone the Repository
```bash
git clone https://github.com/Shahrukhalid/nexonic-reforge-studio.git
cd nexonic-reforge-studio
```

### 2. Create and Activate Virtual Environment
```bash
python -m venv .venv

# Windows (PowerShell)
.venv\Scripts\Activate.ps1

# macOS / Linux (bash/zsh)
source .venv/bin/activate
```

### 3. Install Dependencies
```bash
# Install core package with development tools
pip install -e ".[dev]"

# (Optional) Install dynamic instrumentation bridge
pip install -e ".[dynamic]"
```

### 4. Run the Application
```bash
# Launch GUI Studio
reforge

# Or use the CLI
reforge-cli --help
reforge-cli doctor
```

---

## Running the Automated Test Suite

```bash
# Execute unit and GUI tests
python -m pytest -v

# Run linting and code quality validation
python -m ruff check src tests scripts
```

---

## Packaging Desktop Installers

### Windows Installer (Inno Setup)
```powershell
pyinstaller --noconfirm --distpath dist --workpath build packaging/reforge.spec
& "C:\Program Files (x86)\Inno Setup 6\ISCC.exe" packaging\windows\installer.iss
```

### macOS Disk Image (.dmg)
```bash
pyinstaller --noconfirm --distpath dist --workpath build packaging/reforge.spec
packaging/macos/make_dmg.sh AppleSilicon  # or Intel
```

---

## Security, Privacy & Clean-Room Ethics

Nexonic ReForge Studio is engineered strictly for authorized security research, vulnerability assessment, digital forensics, interoperability development, and clean-room software re-engineering.

- **Process Isolation:** All third-party analysis engines run in isolated subprocesses with enforced execution timeouts, resource boundaries, and sandboxed working directories.
- **Zero Telemetry by Default:** AI assistance and external network connections are strictly opt-in and require user-provided API credentials. No source code, binary payloads, or decompiled outputs are transmitted without explicit user confirmation.
- **Clean-Room Enforcement:** The Reconstruction Studio provides distinct boundaries separating reverse-engineering analysis artifacts from independent re-implementation specifications.

---

## Third-Party Notices

Nexonic ReForge Studio bundles or links against third-party components under compliant open-source licenses:
- **PySide6 / Qt 6**: LGPL-3.0 (dynamically linked)
- **LIEF**: Apache-2.0
- **Capstone Engine**: BSD-3-Clause
- **dnfile**: MIT License
- **olefile**: BSD-2-Clause
- **certifi**: MPL-2.0

See [THIRD_PARTY_NOTICES.md](file:///e:/Github%20Project/Reforge%20Studio/THIRD_PARTY_NOTICES.md) for full licensing disclosures.

---

## License

Copyright © 2026 **Nexonic Technologies**. All Rights Reserved.  
Author: **Shahrukh Khalid**

*Proprietary software. Public availability of this repository does not grant a public open-source license. Unauthorized copying, redistribution, modification, or commercial exploitation without prior written consent from Nexonic Technologies is strictly prohibited.*
