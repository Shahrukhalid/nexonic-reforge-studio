"""Scaffolds independent, clean-room projects based on functional specifications."""
from __future__ import annotations

import json
from pathlib import Path

CLEAN_ROOM_NOTICE = """# Clean-Room Implementation Notice
This codebase was developed independently through clean-room software engineering
based solely on functional requirements, interface specifications, and authorized analysis.
No proprietary source code was copied or directly decompiled into this project.
"""


def scaffold_project(
    dest_dir: Path,
    project_name: str,
    stack: str,
    features: list[dict],
    spec_md: str,
    license_type: str = "MIT",
) -> dict[str, str]:
    """Scaffold a clean-room project structure. Returns map of rel_path -> content."""
    dest_dir.mkdir(parents=True, exist_ok=True)
    stack = stack.lower()
    files: dict[str, str] = {}

    # Specification and Clean-Room notices
    files["SPECIFICATION.md"] = spec_md
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

[tool.pytest.ini_options]
testpaths = ["tests"]
pythonpath = ["src"]
"""
        files["README.md"] = f"# {project_name}\n\nIndependent clean-room reimplementation.\n\n## Usage\n```bash\npip install -e .[dev]\npytest\n```\n"
        files[f"src/{safe_name}/__init__.py"] = f'"""Package {safe_name}."""\n__version__ = "0.1.0"\n'
        files[f"src/{safe_name}/models.py"] = '"""Data models."""\nfrom dataclasses import dataclass\n\n@dataclass\nclass ConfigModel:\n    name: str = "default"\n    enabled: bool = True\n'
        files[f"src/{safe_name}/client.py"] = f'"""API Client implementation."""\nfrom __future__ import annotations\nimport json\nimport urllib.request\n\nclass Client:\n    def __init__(self, base_url: str = "http://localhost:8080"):\n        self.base_url = base_url\n\n    def status(self) -> dict:\n        return {{"status": "ok", "app": "{project_name}"}}\n'
        files[f"src/{safe_name}/main.py"] = '"""Application entry point."""\nfrom .client import Client\n\ndef main():\n    c = Client()\n    print(f"Initialized {c.status()}")\n\nif __name__ == "__main__":\n    main()\n'
        files["tests/test_main.py"] = f'from {safe_name}.client import Client\n\ndef test_client_status():\n    c = Client()\n    res = c.status()\n    assert res["status"] == "ok"\n'

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
        files["src/index.ts"] = f'export function getAppInfo() {{\n  return {{\n    name: "{project_name}",\n    version: "0.1.0",\n    cleanRoom: true\n  }};\n}}\n\nconsole.log(getAppInfo());\n'
        files["tests/index.test.js"] = 'const test = require("node:test");\nconst assert = require("node:assert");\n\ntest("sanity test", () => {\n  assert.strictEqual(1 + 1, 2);\n});\n'

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
        files["src/main.rs"] = f'mod models;\n\nfn main() {{\n    println!("Initialized clean-room {project_name}");\n}}\n\n#[cfg(test)]\nmod tests {{\n    #[test]\n    fn test_init() {{\n        assert_eq!(2 + 2, 4);\n    }}\n}}\n'

    elif stack == "go":
        files["go.mod"] = f"module {safe_name}\n\ngo 1.21\n"
        files["README.md"] = f"# {project_name}\n\nClean-room Go implementation.\n\n## Build & Test\n```bash\ngo test ./...\ngo run main.go\n```\n"
        files["models/models.go"] = 'package models\n\ntype ConfigModel struct {\n\tName    string `json:"name"`\n\tEnabled bool   `json:"enabled"`\n}\n'
        files["main.go"] = f'package main\n\nimport "fmt"\n\nfunc main() {{\n\tfmt.Println("Starting clean-room {project_name}")\n}}\n'
        files["main_test.go"] = 'package main\n\nimport "testing"\n\nfunc TestMain(t *testing.T) {\n\tif 1 != 1 {\n\t\tt.Fail()\n\t}\n}\n'

    else:
        # Generic / C# default
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
