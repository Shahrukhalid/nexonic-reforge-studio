"""Persistent analysis and decompilation caching engine.

Caches expensive analysis stage outputs (such as Ghidra decompilation, Capstone disassembly,
and AST extraction) keyed by the SHA-256 digest of the input binary and tool name.
Avoids redundant re-processing when re-analyzing or analyzing across profiles.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..core import paths
from ..core.findings import Finding


class AnalysisCache:
    """Manages cache entries for tool findings on disk."""

    def __init__(self, cache_dir: Path | None = None):
        self.cache_dir = cache_dir or (paths.data_dir() / "cache" / "analysis")
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    def _key_path(self, file_sha256: str, tool: str, stage: str) -> Path:
        safe_tool = "".join(c if c.isalnum() else "_" for c in tool.lower())
        safe_stage = "".join(c if c.isalnum() else "_" for c in stage.lower())
        return self.cache_dir / f"{file_sha256[:16]}_{safe_tool}_{safe_stage}.json"

    def get(self, file_sha256: str, tool: str, stage: str) -> list[dict[str, Any]] | None:
        """Retrieve cached findings if available."""
        if not file_sha256:
            return None
        p = self._key_path(file_sha256, tool, stage)
        if not p.is_file():
            return None
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
            if isinstance(data, list):
                return data
        except Exception:
            return None
        return None

    def get_findings(self, file_sha256: str, tool: str, stage: str) -> list[Finding] | None:
        """Retrieve cached findings deserialized as Finding instances with enum validation."""
        cached = self.get(file_sha256, tool, stage)
        if cached is None:
            return None
        out: list[Finding] = []
        for item in cached:
            if isinstance(item, dict):
                try:
                    out.append(Finding.from_dict(item))
                except Exception:
                    pass
        return out

    def put(self, file_sha256: str, tool: str, stage: str, items: list[Finding]) -> None:
        """Store findings in persistent cache."""
        if not file_sha256 or not items:
            return
        p = self._key_path(file_sha256, tool, stage)
        try:
            records = [item.to_dict() for item in items]
            p.write_text(json.dumps(records, indent=2), encoding="utf-8")
        except Exception:
            pass

    def clear(self) -> int:
        """Remove all cache entries and return count of deleted files."""
        count = 0
        if self.cache_dir.is_dir():
            for f in self.cache_dir.glob("*.json"):
                try:
                    f.unlink()
                    count += 1
                except Exception:
                    pass
        return count

    def stats(self) -> tuple[int, int]:
        """Return (number of cached items, total bytes)."""
        count = 0
        total_bytes = 0
        if self.cache_dir.is_dir():
            for f in self.cache_dir.glob("*.json"):
                if f.is_file():
                    count += 1
                    total_bytes += f.stat().st_size
        return count, total_bytes
