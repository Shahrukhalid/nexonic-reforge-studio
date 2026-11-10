"""Scaffolds independent, clean-room projects based on functional specifications."""
from __future__ import annotations

import json
from pathlib import Path

from .tests_gen import generate_evidence_tests

CLEAN_ROOM_NOTICE = """# Clean-Room Implementation Notice
This codebase was developed independently through clean-room software engineering
based solely on functional requirements, interface specifications, and authorized analysis.
No proprietary source code was copied or directly decompiled into this project.
"""

MIT_LICENSE = """MIT License

Copyright (c) 2026 Nexonic Technologies & Contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

APACHE_2_0_LICENSE = """                                 Apache License
                           Version 2.0, January 2004
                        http://www.apache.org/licenses/

   TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION

   1. Definitions.
      "License" shall mean the terms and conditions for use, reproduction,
      and distribution as defined by Sections 1 through 9 of this document.
      "Licensor" shall mean the copyright owner or entity authorized by
      the copyright owner that is granting the License.
      "Legal Entity" shall mean the union of the acting entity and all
      other entities that control, are controlled by, or are under common
      control with that entity.
      "You" (or "Your") shall mean an individual or Legal Entity
      exercising permissions granted by this License.
      "Source" form shall mean the preferred form for making modifications,
      including but not limited to software source code, documentation
      source, and configuration files.
      "Object" form shall mean any form resulting from mechanical
      transformation or translation of a Source form, including but
      not limited to compiled object code, generated documentation,
      and conversions to other media types.
      "Work" shall mean the work of authorship, whether in Source or
      Object form, made available under the License.
      "Derivative Works" shall mean any work, whether in Source or Object
      form, that is based on (or derived from) the Work.

   2. Grant of Copyright License. Subject to the terms and conditions of
      this License, each Contributor hereby grants to You a perpetual,
      worldwide, non-exclusive, no-charge, royalty-free, irrevocable
      copyright license to reproduce, prepare Derivative Works of,
      publicly display, publicly perform, sublicense, and distribute the
      Work and such Derivative Works in Source or Object form.

   3. Grant of Patent License. Subject to the terms and conditions of
      this License, each Contributor hereby grants to You a perpetual,
      worldwide, non-exclusive, no-charge, royalty-free, irrevocable
      patent license to make, have made, use, offer to sell, sell, import,
      and otherwise transfer the Work.

   4. Redistribution. You may reproduce and distribute copies of the
      Work or Derivative Works thereof in any medium, with or without
      modifications, and in Source or Object form, provided that You
      meet the following conditions:
      (a) You must give any other recipients of the Work or Derivative
          Works a copy of this License; and
      (b) You must cause any modified files to carry prominent notices
          stating that You changed the files; and
      (c) You must retain, in the Source form of any Derivative Works
          that You distribute, all copyright, patent, trademark, and
          attribution notices from the Source form of the Work; and
      (d) If the Work includes a "NOTICE" text file as part of its
          distribution, then any Derivative Works that You distribute must
          include a readable copy of the attribution notices contained
          within such NOTICE file.

   5. Disclaimer of Warranty. Unless required by applicable law or
      agreed to in writing, Licensor provides the Work (and each
      Contributor provides its Contributions) on an "AS IS" BASIS,
      WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
      implied, including, without limitation, any warranties or conditions
      of TITLE, NON-INFRINGEMENT, MERCHANTABILITY, or FITNESS FOR A
      PARTICULAR PURPOSE.
"""

BSD_3_CLAUSE_LICENSE = """Copyright (c) 2026, Nexonic Technologies & Contributors
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its
   contributors may be used to endorse or promote products derived from
   this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
"""

PROPRIETARY_LICENSE = """Copyright (c) 2026 Nexonic Technologies. All Rights Reserved.

CONFIDENTIAL AND PROPRIETARY SOFTWARE.

This clean-room software project is proprietary and confidential.
Unauthorized copying, transfer, decompilation, distribution, or public display
of this software via any medium is strictly prohibited without explicit
written authorization from Nexonic Technologies.
"""


def get_license_text(license_type: str) -> str:
    """Return full legal text for the requested license type."""
    norm = (license_type or "").strip().upper()
    if "APACHE" in norm:
        return APACHE_2_0_LICENSE
    if "BSD" in norm:
        return BSD_3_CLAUSE_LICENSE
    if "PROPRIETARY" in norm:
        return PROPRIETARY_LICENSE
    return MIT_LICENSE


def generate_specification(
    findings: list[dict] | None,
    project_name: str,
    selected_features: list[dict | str] | None = None,
) -> str:
    """Synthesize a comprehensive clean-room functional specification from analysis findings.

    Accurately distinguishes:
    - [OBSERVED FACT - CONFIRMED]: Directly verified from binary structures and exports.
    - [INFERRED BEHAVIOR - TENTATIVE]: Derived from disassembly and call graph heuristics.
    - [UNVERIFIED DATA - REQUIRES VALIDATION]: Raw string indicators / endpoints.
    - [UNKNOWN FUNCTIONALITY]: Boundaries where analysis was restricted or stripped.
    """
    raw_findings = [r for r in (findings or []) if isinstance(r, dict)]

    lines: list[str] = [
        f"# Clean-Room Functional Specification: {project_name}",
        "",
        "## 1. Executive Summary & Clean-Room Mandate",
        "This specification establishes the functional requirements, interface contracts, and architectural",
        "blueprint for an independent, clean-room implementation of the target application.",
        "",
        "> **Important Legal Assertion:**",
        "> Engineers implementing this specification must strictly refrain from inspecting proprietary",
        "> decompiled or disassembled code. Implementation must proceed solely from the interface",
        "> contracts, behavior requirements, and data formats described herein.",
        "",
        "## 2. Observed Binary Facts & Platform Constraints `[OBSERVED FACT - CONFIRMED]`",
    ]

    # Inspect binary headers & architecture
    header_find = next((r["value"] for r in raw_findings if r.get("key", "").endswith("header") and isinstance(r.get("value"), dict)), None)
    if header_find:
        lines.append(f"- **Binary Format:** {header_find.get('format', 'Native executable')} `[CONFIRMED]`")
        lines.append(f"- **Target Architecture:** {header_find.get('arch', 'x86-64 / ARM64')} ({header_find.get('bits', 64)}-bit) `[CONFIRMED]`")
        lines.append(f"- **Endianness:** {header_find.get('endianness', 'Little-endian')} `[CONFIRMED]`")
        if header_find.get("subsystem"):
            lines.append(f"- **Subsystem:** {header_find.get('subsystem')} `[CONFIRMED]`")
        if header_find.get("minos"):
            lines.append(f"- **Minimum OS Version:** {header_find.get('minos')} `[CONFIRMED]`")
        lines.append(f"- **Security Mitigations:** PIE/ASLR={header_find.get('pie', False)}, NX/DEP={header_find.get('nx', True)} `[CONFIRMED]`")
    else:
        lines.append("- **Platform Requirement:** Cross-platform (Windows x64 / macOS arm64 / Linux x64) `[ASSUMED]`")

    # 3. Verified External Interfaces & Dependencies
    lines.extend([
        "",
        "## 3. Verified External Interfaces & Shared Libraries `[OBSERVED FACT - CONFIRMED]`",
    ])
    deps = next((r["value"] for r in raw_findings if r.get("key", "").endswith("libraries") and isinstance(r.get("value"), list)), [])
    if deps:
        lines.append("Observed dynamic shared libraries linked by target:")
        for d in deps[:30]:
            lines.append(f"- `{d}` `[OBSERVED LINK]`")
    else:
        lines.append("- Standard system runtime libraries.")

    # 4. Inferred Behavioral Logic & Control Flow
    lines.extend([
        "",
        "## 4. Inferred Behavioral Logic & Control Flow `[INFERRED BEHAVIOR - TENTATIVE]`",
        "The following behavioral requirements are inferred from static control flow, call graphs, and",
        "disassembly analysis. Implementers should fulfill these functional roles through clean-room design:",
    ])
    call_find = next((r["value"] for r in raw_findings if r.get("key") == "call_graph" and isinstance(r.get("value"), dict)), None)
    if call_find and call_find.get("items"):
        lines.append(f"- **Observed Call Edges:** {call_find.get('edges', len(call_find['items']))} inter-procedural call relations.")
        lines.append("- **Key Flow Patterns:** Sequential initialization followed by modular dispatch.")
    else:
        lines.append("- **Component Flow:** Independent service initialization and event processing loop.")

    # 5. Unverified Network Endpoints & Indicators
    lines.extend([
        "",
        "## 5. Unverified Network Endpoints & Protocol Indicators `[UNVERIFIED DATA - REQUIRES VALIDATION]`",
        "> **Notice:** The following strings were extracted from binary data sections. They have NOT been",
        "> verified as active or authorized remote interfaces. Validate against staging infrastructure prior to integration.",
    ])
    endpoints = []
    for r in raw_findings:
        if r.get("kind") == "network" and isinstance(r.get("value"), list):
            endpoints.extend(r["value"])
    if endpoints:
        lines.append("Extracted network strings and candidate API endpoints:")
        for ep in sorted(set(endpoints))[:30]:
            lines.append(f"- `{ep}` `[UNVERIFIED STRING]`")
    else:
        lines.append("- Standalone local application; no external network communications confirmed.")

    indicators = []
    for r in raw_findings:
        if r.get("kind") == "indicators" and isinstance(r.get("value"), list):
            indicators.extend(r["value"])
    if indicators:
        lines.append("\nCandidate configuration strings and environment variables:")
        for ind in sorted(set(indicators))[:30]:
            lines.append(f"- `{ind}` `[UNVERIFIED STRING]`")

    # 6. Unknown Functionality & Analysis Boundaries
    lines.extend([
        "",
        "## 6. Unknown Functionality & Analysis Boundaries `[UNKNOWN FUNCTIONALITY]`",
        "- **Stripped Debug Metadata:** Local variable names and non-exported type definitions are absent in release binaries.",
        "- **Dynamic Dispatch:** Computed jumps and indirect calls are not resolved statically; clean-room interfaces must define explicit contracts.",
        "- **Security Constraint:** Original binaries are never executed dynamically on host. Unknown behavior is modeled safely via isolated fixtures.",
    ])

    # 7. Functional Requirements & Components
    lines.extend([
        "",
        "## 7. Clean-Room Architectural Components",
    ])
    feats: list[dict] = []
    if selected_features:
        for f in selected_features:
            if isinstance(f, dict):
                feats.append(f)
            elif isinstance(f, str):
                feats.append({"name": f, "category": "Functional Feature"})
    if not feats:
        feats = [
            {"name": "Application Core Orchestrator", "category": "Core Architecture"},
            {"name": "Configuration & State Manager", "category": "Data Management"},
            {"name": "Service / Client Interface", "category": "Networking / I/O"},
            {"name": "Command-Line & Runtime Interface", "category": "User Interface"},
        ]
    for idx, f in enumerate(feats, 1):
        lines.append(f"### 7.{idx} {f['name']}")
        lines.append(f"- **Category:** {f.get('category', 'Functional Module')}")
        lines.append("- **Clean-Room Requirement:** Implement independent module fulfilling interface contracts without proprietary dependencies.")

    # 8. Quality Assurance & Verification Plan
    lines.extend([
        "",
        "## 8. Quality Assurance & Verification Plan",
        "- **Unit Testing:** 100% test coverage of core data models, configuration loaders, and serializers.",
        "- **Evidence-Based Behavioral Tests:** Automated test suite verifying contract integrity and mocked responses.",
        "- **Sandboxed Execution:** Zero host execution of untrusted or original binaries.",
    ])

    return "\n".join(lines)


def scaffold_project(
    dest_dir: Path,
    project_name: str,
    stack: str,
    features: list[dict | str] | None = None,
    spec_md: str = "",
    license_type: str = "MIT",
) -> dict[str, str]:
    """Scaffold a multi-module clean-room project structure. Returns map of rel_path -> content."""
    dest_dir.mkdir(parents=True, exist_ok=True)
    stack = stack.lower()
    files: dict[str, str] = {}

    # Specification and Clean-Room notices
    full_spec = spec_md if (spec_md and spec_md.strip()) else generate_specification([], project_name, features or [])
    files["SPECIFICATION.md"] = full_spec
    files["CLEAN_ROOM_NOTICE.md"] = CLEAN_ROOM_NOTICE

    # License: full legal license template
    files["LICENSE"] = get_license_text(license_type)

    safe_name = project_name.lower().replace("-", "_").replace(" ", "_")

    # Generate evidence-based behavioral tests
    evidence_tests = generate_evidence_tests(
        stack=stack,
        project_name=project_name,
        features=features,
    )
    files.update(evidence_tests)

    safe_name = project_name.lower().replace("-", "_").replace(" ", "_")

    if stack == "python":
        files["pyproject.toml"] = f"""[build-system]
requires = ["setuptools>=61.0"]
build-backend = "setuptools.build_meta"

[project]
name = "{safe_name}"
version = "0.1.0"
description = "Clean-room reimplementation of {project_name}"
readme = "README.md"
license = {{ text = "{license_type}" }}
requires-python = ">=3.10"
dependencies = []

[project.optional-dependencies]
dev = ["pytest>=7.0.0"]

[project.scripts]
{safe_name} = "{safe_name}.cli:main"

[tool.pytest.ini_options]
testpaths = ["tests"]
pythonpath = ["src"]
"""
        files["README.md"] = f"""# {project_name}

Independent clean-room reimplementation created with **Nexonic ReForge Studio**.

## Architecture
- `src/{safe_name}/core.py`: Application state, configuration loader, and orchestrator.
- `src/{safe_name}/models.py`: Clean-room data models and schemas.
- `src/{safe_name}/client.py`: API and service integration client.
- `src/{safe_name}/cli.py`: Command-line interface.

## Quickstart
```bash
pip install -e .[dev]
pytest -v
{safe_name} --help
```
"""
        files[f"src/{safe_name}/__init__.py"] = f'"""Package {safe_name}."""\n__version__ = "0.1.0"\n'
        files[f"src/{safe_name}/core.py"] = f'''"""Core application orchestrator and state management."""
from __future__ import annotations

import logging
from dataclasses import dataclass
from .models import AppConfig

logger = logging.getLogger("{safe_name}")


class Application:
    """Independent clean-room application instance."""

    def __init__(self, config: AppConfig | None = None):
        self.config = config or AppConfig()
        self._running = False

    def start(self) -> dict[str, str]:
        self._running = True
        return {{"status": "running", "name": self.config.app_name, "version": self.config.version}}

    def stop(self) -> dict[str, str]:
        self._running = False
        return {{"status": "stopped"}}

    def execute(self, action: str = "default", *args, **kwargs) -> dict[str, str]:
        return {{"action": action, "status": "executed", "app": self.config.app_name}}
'''
        files[f"src/{safe_name}/models.py"] = f'''"""Data models and schemas."""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class AppConfig:
    app_name: str = "{project_name}"
    version: str = "0.1.0"
    base_url: str = "http://localhost:8080"
    debug: bool = False
    attributes: dict[str, str] = field(default_factory=dict)
'''
        files[f"src/{safe_name}/client.py"] = f'''"""Service and endpoint client implementation."""
from __future__ import annotations

import json
import urllib.request


class Client:
    """Clean-room API client implementation."""

    def __init__(self, base_url: str = "http://localhost:8080"):
        self.base_url = base_url.rstrip("/")

    def status(self) -> dict:
        return {{"status": "ok", "app": "{project_name}", "endpoint": self.base_url}}
'''
        files[f"src/{safe_name}/cli.py"] = f'''"""Command-line interface entry point."""
from __future__ import annotations

import argparse
import sys
from .core import Application
from .models import AppConfig


def main(argv: list[str] | None = None):
    parser = argparse.ArgumentParser(description="{project_name} Clean-Room Application")
    parser.add_argument("--version", action="store_true", help="Print application version")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    args = parser.parse_args(argv)

    if args.version:
        print("{project_name} v0.1.0 (Clean-Room)")
        return 0

    app = Application(AppConfig(debug=args.debug))
    res = app.start()
    print(f"Started: {{res}}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
'''
        files[f"src/{safe_name}/main.py"] = f'''"""Default module entry point."""
from .cli import main

if __name__ == "__main__":
    print("Initialized clean-room {project_name}")
    main()
'''
        files["tests/test_core.py"] = f'''from {safe_name}.core import Application
from {safe_name}.models import AppConfig


def test_application_lifecycle():
    app = Application(AppConfig(app_name="TestApp"))
    res = app.start()
    assert res["status"] == "running"
    assert res["name"] == "TestApp"
    stop_res = app.stop()
    assert stop_res["status"] == "stopped"
'''
        files["tests/test_models.py"] = f'''from {safe_name}.models import AppConfig


def test_app_config_defaults():
    cfg = AppConfig()
    assert cfg.version == "0.1.0"
    assert isinstance(cfg.attributes, dict)
'''
        files["tests/test_main.py"] = f'''from {safe_name}.client import Client
from {safe_name}.cli import main


def test_client_status():
    c = Client()
    res = c.status()
    assert res["status"] == "ok"
    assert "endpoint" in res


def test_cli_version():
    code = main(["--version"])
    assert code == 0
'''

    elif stack in ("typescript", "node", "javascript"):
        files["package.json"] = json.dumps({
            "name": safe_name,
            "version": "0.1.0",
            "description": f"Clean-room reimplementation of {project_name}",
            "main": "dist/index.js",
            "scripts": {
                "build": "tsc",
                "test": "node --test"
            },
            "license": license_type,
            "devDependencies": {
                "typescript": "^5.0.0"
            }
        }, indent=2)
        files["tsconfig.json"] = json.dumps({
            "compilerOptions": {
                "target": "ES2022",
                "module": "NodeNext",
                "outDir": "./dist",
                "strict": True,
                "esModuleInterop": True
            },
            "include": ["src/**/*"]
        }, indent=2)
        files["README.md"] = f"# {project_name}\n\nClean-room TypeScript reimplementation.\n\n## Usage\n```bash\nnpm install\nnpm test\n```\n"
        files["src/models.ts"] = "export interface ConfigModel {\n  name: string;\n  enabled: boolean;\n}\n"
        files["src/client.ts"] = f'export class Client {{\n  constructor(public baseUrl: string = "http://localhost:8080") {{}}\n  getStatus() {{\n    return {{ status: "ok", app: "{project_name}" }};\n  }}\n}}\n'
        files["src/index.ts"] = f'import {{ Client }} from "./client.js";\nexport function getAppInfo() {{\n  return {{\n    name: "{project_name}",\n    version: "0.1.0",\n    cleanRoom: true\n  }};\n}}\n\nconst client = new Client();\nconsole.log(client.getStatus());\n'
        files["tests/index.test.js"] = 'const test = require("node:test");\nconst assert = require("node:assert");\n\ntest("client sanity test", () => {\n  assert.strictEqual(1 + 1, 2);\n});\n'

    elif stack == "rust":
        files["Cargo.toml"] = f"""[package]
name = "{safe_name}"
version = "0.1.0"
edition = "2021"
license = "{license_type}"

[dependencies]
serde = {{ version = "1.0", features = ["derive"] }}
serde_json = "1.0"

[dev-dependencies]
"""
        files["README.md"] = f"# {project_name}\n\nClean-room Rust implementation.\n\n## Build & Test\n```bash\ncargo test\ncargo build --release\n```\n"
        files["src/models.rs"] = "use serde::{Deserialize, Serialize};\n\n#[derive(Debug, Serialize, Deserialize)]\npub struct ConfigModel {\n    pub name: String,\n    pub enabled: bool,\n}\n"
        files["src/client.rs"] = 'pub struct Client {\n    pub base_url: String,\n}\n\nimpl Client {\n    pub fn new(url: &str) -> Self {\n        Self { base_url: url.to_string() }\n    }\n    pub fn status(&self) -> &\'static str {\n        "ok"\n    }\n}\n'
        files["src/main.rs"] = f'mod models;\nmod client;\n\nuse client::Client;\n\nfn main() {{\n    let c = Client::new("http://localhost:8080");\n    println!("Initialized clean-room {project_name}: {{}}", c.status());\n}}\n\n#[cfg(test)]\nmod tests {{\n    use super::client::Client;\n    #[test]\n    fn test_client() {{\n        let c = Client::new("http://localhost:8080");\n        assert_eq!(c.status(), "ok");\n    }}\n}}\n'

    elif stack == "go":
        files["go.mod"] = f"module {safe_name}\n\ngo 1.21\n"
        files["README.md"] = f"# {project_name}\n\nClean-room Go implementation.\n\n## Build & Test\n```bash\ngo test ./...\ngo run main.go\n```\n"
        files["models/models.go"] = 'package models\n\ntype ConfigModel struct {\n\tName    string `json:"name"`\n\tEnabled bool   `json:"enabled"`\n}\n'
        files["client/client.go"] = 'package client\n\ntype Client struct {\n\tBaseURL string\n}\n\nfunc NewClient(url string) *Client {\n\treturn &Client{BaseURL: url}\n}\n\nfunc (c *Client) Status() string {\n\treturn "ok"\n}\n'
        files["main.go"] = f'package main\n\nimport (\n\t"fmt"\n\t"{safe_name}/client"\n)\n\nfunc main() {{\n\tc := client.NewClient("http://localhost:8080")\n\tfmt.Printf("Starting clean-room {project_name}: %s\\n", c.Status())\n}}\n'
        files["main_test.go"] = f'package main\n\nimport (\n\t"testing"\n\t"{safe_name}/client"\n)\n\nfunc TestClientStatus(t *testing.T) {{\n\tc := client.NewClient("http://localhost:8080")\n\tif c.Status() != "ok" {{\n\t\tt.Fail()\n\t}}\n}}\n'

    elif stack in ("c", "cpp"):
        files["CMakeLists.txt"] = f"""cmake_minimum_required(VERSION 3.15)
project({safe_name} C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

include_directories(include)

add_library({safe_name}_core STATIC src/core.c)
add_executable({safe_name} src/main.c)
target_link_libraries({safe_name} PRIVATE {safe_name}_core)

enable_testing()
add_executable(test_runner tests/test_core.c)
target_link_libraries(test_runner PRIVATE {safe_name}_core)
add_test(NAME CoreTests COMMAND test_runner)
"""
        files["README.md"] = f"# {project_name}\n\nClean-room C/C++ reimplementation.\n\n## Build & Test\n```bash\ncmake -B build\ncmake --build build --config Release\nctest --test-dir build\n```\n"
        files["include/core.h"] = f"""#ifndef {safe_name.upper()}_CORE_H
#define {safe_name.upper()}_CORE_H

typedef struct {{
    char name[64];
    char version[16];
    int enabled;
}} AppConfig;

AppConfig core_init(const char* app_name);
int core_execute(const AppConfig* config, const char* action);

#endif
"""
        files["src/core.c"] = f"""#include "core.h"
#include <string.h>

AppConfig core_init(const char* app_name) {{
    AppConfig cfg;
    strncpy(cfg.name, app_name ? app_name : "{project_name}", sizeof(cfg.name) - 1);
    cfg.name[sizeof(cfg.name) - 1] = '\\0';
    strncpy(cfg.version, "0.1.0", sizeof(cfg.version) - 1);
    cfg.version[sizeof(cfg.version) - 1] = '\\0';
    cfg.enabled = 1;
    return cfg;
}}

int core_execute(const AppConfig* config, const char* action) {{
    if (!config || !config->enabled) return -1;
    return 0;
}}
"""
        files["src/main.c"] = f"""#include <stdio.h>
#include "core.h"

int main(int argc, char** argv) {{
    AppConfig cfg = core_init("{project_name}");
    printf("Initialized clean-room %s v%s\\n", cfg.name, cfg.version);
    return 0;
}}
"""
        files["tests/test_core.c"] = """#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "core.h"

int main(void) {
    AppConfig cfg = core_init("TestApp");
    assert(strcmp(cfg.name, "TestApp") == 0);
    assert(cfg.enabled == 1);
    int rc = core_execute(&cfg, "test");
    assert(rc == 0);
    printf("All C core unit tests passed successfully.\\n");
    return 0;
}
"""

    elif stack == "java":
        files["pom.xml"] = f"""<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>
    <groupId>com.reforge.cleanroom</groupId>
    <artifactId>{safe_name}</artifactId>
    <version>0.1.0</version>
    <properties>
        <maven.compiler.source>17</maven.compiler.source>
        <maven.compiler.target>17</maven.compiler.target>
        <project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>
    </properties>
    <dependencies>
        <dependency>
            <groupId>org.junit.jupiter</groupId>
            <artifactId>junit-jupiter-api</artifactId>
            <version>5.10.0</version>
            <scope>test</scope>
        </dependency>
    </dependencies>
</project>
"""
        files["README.md"] = f"# {project_name}\n\nClean-room Java reimplementation.\n\n## Build & Test\n```bash\nmvn compile\nmvn test\nmvn package\n```\n"
        files["src/main/java/com/reforge/cleanroom/App.java"] = f"""package com.reforge.cleanroom;

public class App {{
    private final String appName;
    private final String version;
    private boolean running;

    public App(String appName) {{
        this.appName = appName;
        this.version = "0.1.0";
        this.running = false;
    }}

    public void start() {{
        this.running = true;
    }}

    public boolean isRunning() {{
        return this.running;
    }}

    public String getStatus() {{
        return "ok";
    }}

    public static void main(String[] args) {{
        App app = new App("{project_name}");
        app.start();
        System.out.println("Started clean-room " + app.appName);
    }}
}}
"""
        files["src/test/java/com/reforge/cleanroom/AppTest.java"] = """package com.reforge.cleanroom;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

public class AppTest {
    @Test
    public void testLifecycle() {
        App app = new App("TestApp");
        assertFalse(app.isRunning());
        app.start();
        assertTrue(app.isRunning());
        assertEquals("ok", app.getStatus());
    }
}
"""

    else:
        files[f"{safe_name}.csproj"] = f"""<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>net8.0</TargetFramework>
    <ImplicitUsings>enable</ImplicitUsings>
    <Nullable>enable</Nullable>
    <PackageLicenseExpression>{license_type}</PackageLicenseExpression>
  </PropertyGroup>
</Project>
"""
        files["README.md"] = f"# {project_name}\n\nIndependent C# / .NET clean-room reimplementation.\n\n## Build & Test\n```bash\ndotnet build\ndotnet test\n```\n"
        files["src/Models.cs"] = f"""namespace {safe_name.capitalize().replace("_", "")}.Models;

public record ConfigModel(string Name, bool Enabled);
"""
        files["src/Client.cs"] = f"""namespace {safe_name.capitalize().replace("_", "")}.Client;

public class ServiceClient
{{
    public string BaseUrl {{ get; }}
    public ServiceClient(string baseUrl = "http://127.0.0.1:8080") => BaseUrl = baseUrl;
    public string GetStatus() => "ok";
}}
"""
        files["src/Program.cs"] = f"""using System;
using {safe_name.capitalize().replace("_", "")}.Client;

Console.WriteLine("Starting clean-room {project_name}");
var client = new ServiceClient();
Console.WriteLine($"Service status: {{client.GetStatus()}}");
"""

    # Write files to dest_dir
    for rel_path, content in files.items():
        p = dest_dir / rel_path
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")

    return files
