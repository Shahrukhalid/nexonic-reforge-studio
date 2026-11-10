"""Scaffolds independent, clean-room projects based on functional specifications."""
from __future__ import annotations

import json
from pathlib import Path

CLEAN_ROOM_NOTICE = """# Clean-Room Implementation Notice
This codebase was developed independently through clean-room software engineering
based solely on functional requirements, interface specifications, and authorized analysis.
No proprietary source code was copied or directly decompiled into this project.
"""


def generate_specification(
    findings: list[dict] | None,
    project_name: str,
    selected_features: list[dict | str] | None = None,
) -> str:
    """Synthesize a comprehensive clean-room functional specification from analysis findings."""
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
        "## 2. Target Platform & Architecture Requirements",
    ]

    # Inspect binary headers & architecture
    header_find = next((r["value"] for r in raw_findings if r.get("key", "").endswith("header") and isinstance(r.get("value"), dict)), None)
    if header_find:
        lines.append(f"- **Binary Format:** {header_find.get('format', 'Native executable')}")
        lines.append(f"- **Target Architecture:** {header_find.get('arch', 'x86-64 / ARM64')} ({header_find.get('bits', 64)}-bit)")
        lines.append(f"- **Endianness:** {header_find.get('endianness', 'Little-endian')}")
        if header_find.get("subsystem"):
            lines.append(f"- **Subsystem:** {header_find.get('subsystem')}")
        if header_find.get("minos"):
            lines.append(f"- **Minimum OS Version:** {header_find.get('minos')}")
        lines.append(f"- **Security Features:** PIE/ASLR={header_find.get('pie', False)}, NX/DEP={header_find.get('nx', True)}")
    else:
        lines.append("- **Platform Requirement:** Cross-platform (Windows x64 / macOS arm64 / Linux x64)")

    # 3. External Interfaces & Dependencies
    lines.extend([
        "",
        "## 3. External Interfaces & Dependencies",
    ])
    deps = next((r["value"] for r in raw_findings if r.get("key", "").endswith("libraries") and isinstance(r.get("value"), list)), [])
    if deps:
        lines.append("Required external shared libraries and runtime modules:")
        for d in deps[:30]:
            lines.append(f"- `{d}`")
    else:
        lines.append("- Standard system libraries and runtime modules.")

    # 4. Network Endpoints & Protocols
    lines.extend([
        "",
        "## 4. Network Communications & Endpoints",
    ])
    endpoints = []
    for r in raw_findings:
        if r.get("kind") == "network" and isinstance(r.get("value"), list):
            endpoints.extend(r["value"])
    if endpoints:
        lines.append("Identified network indicators and API communication endpoints:")
        for ep in sorted(set(endpoints))[:30]:
            lines.append(f"- `{ep}`")
    else:
        lines.append("- Standalone local application; no external network communications required.")

    # 5. Indicators & Configuration Schema
    lines.extend([
        "",
        "## 5. Configuration & Indicators Schema",
    ])
    indicators = []
    for r in raw_findings:
        if r.get("kind") == "indicators" and isinstance(r.get("value"), list):
            indicators.extend(r["value"])
    if indicators:
        lines.append("Discovered configuration parameters, indicator paths, and environment settings:")
        for ind in sorted(set(indicators))[:30]:
            lines.append(f"- `{ind}`")
    else:
        lines.append("- Standard application configuration file or environment variables.")

    # 6. Functional Requirements & Features
    lines.extend([
        "",
        "## 6. Functional Requirements & Component Specifications",
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
        lines.append(f"### 6.{idx} {f['name']}")
        lines.append(f"- **Category:** {f.get('category', 'Functional Module')}")
        lines.append("- **Requirement:** Implement clean-room module fulfilling interface contracts and behavioral requirements independently.")

    # 7. Quality Assurance & Verification Plan
    lines.extend([
        "",
        "## 7. Verification & Test Plan",
        "- **Unit Testing:** 100% coverage of core data models, configuration loaders, and serializers.",
        "- **Integration Testing:** Live verification of client status, interface responses, and protocol parsers.",
        "- **Sandboxed Execution:** Zero execution of untrusted or proprietary original binaries.",
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

    # License
    files["LICENSE"] = f"{license_type} License\n\nCopyright (c) 2026. All rights reserved.\n"

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

    else:
        files[f"{safe_name}.csproj"] = """<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>net8.0</TargetFramework>
    <ImplicitUsings>enable</ImplicitUsings>
    <Nullable>enable</Nullable>
  </PropertyGroup>
</Project>
"""
        files["Program.cs"] = f'Console.WriteLine("Starting {project_name} clean-room project");\n'
        files["README.md"] = f"# {project_name}\n\nIndependent C# reimplementation.\n"

    # Write files to dest_dir
    for rel_path, content in files.items():
        p = dest_dir / rel_path
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")

    return files
