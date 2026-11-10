"""SQLite project store. Large artifacts live on disk; the DB keeps metadata only."""
from __future__ import annotations

import json
import shutil
import sqlite3
import threading
import time
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from . import paths
from .findings import Finding

SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS projects(
  id INTEGER PRIMARY KEY, name TEXT NOT NULL, input_path TEXT NOT NULL,
  sha256 TEXT, size INTEGER, profile TEXT, status TEXT NOT NULL DEFAULT 'new',
  created REAL NOT NULL, updated REAL NOT NULL, workdir TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS findings(
  id INTEGER PRIMARY KEY, project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  stage TEXT, tool TEXT, kind TEXT, key TEXT, value TEXT, confidence TEXT, provenance TEXT,
  evidence TEXT, subject TEXT, extra TEXT);
CREATE INDEX IF NOT EXISTS ix_findings_project ON findings(project_id, stage, kind);
CREATE TABLE IF NOT EXISTS tool_runs(
  id INTEGER PRIMARY KEY, project_id INTEGER REFERENCES projects(id) ON DELETE CASCADE,
  tool TEXT, command TEXT, started REAL, ended REAL, status TEXT, message TEXT);
CREATE TABLE IF NOT EXISTS artifacts(
  id INTEGER PRIMARY KEY, project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  rel_path TEXT, kind TEXT, size INTEGER, sha256 TEXT);
CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT);
"""
SCHEMA_VERSION = "1"


class Database:
    def __init__(self, path: Path | None = None):
        self.path = Path(path or paths.db_path())
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.executescript(SCHEMA)
            self._conn.execute("INSERT OR IGNORE INTO meta VALUES('schema_version', ?)", (SCHEMA_VERSION,))
            self._conn.commit()

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def _exec(self, sql: str, args: Iterable[Any] = ()) -> sqlite3.Cursor:
        with self._lock:
            cur = self._conn.execute(sql, tuple(args))
            self._conn.commit()
            return cur

    def _all(self, sql: str, args: Iterable[Any] = ()) -> list[dict]:
        with self._lock:
            return [dict(r) for r in self._conn.execute(sql, tuple(args)).fetchall()]

    # projects -------------------------------------------------------------
    def create_project(self, name: str, input_path: str, profile: str = "standard") -> int:
        now = time.time()
        cur = self._exec(
            "INSERT INTO projects(name,input_path,profile,status,created,updated,workdir) VALUES(?,?,?,?,?,?,?)",
            (name, input_path, profile, "new", now, now, ""),
        )
        pid = int(cur.lastrowid)
        wd = paths.projects_dir() / f"p{pid:05d}"
        wd.mkdir(parents=True, exist_ok=True)
        self._exec("UPDATE projects SET workdir=? WHERE id=?", (str(wd), pid))
        return pid

    def update_project(self, pid: int, **fields: Any) -> None:
        allowed = {"name", "sha256", "size", "profile", "status"}
        sets = {k: v for k, v in fields.items() if k in allowed}
        if not sets:
            return
        cols = ", ".join(f"{k}=?" for k in sets)
        self._exec(f"UPDATE projects SET {cols}, updated=? WHERE id=?", (*sets.values(), time.time(), pid))

    def project(self, pid: int) -> dict | None:
        rows = self._all("SELECT * FROM projects WHERE id=?", (pid,))
        return rows[0] if rows else None

    def projects(self, limit: int = 200) -> list[dict]:
        return self._all("SELECT * FROM projects ORDER BY updated DESC LIMIT ?", (limit,))

    def delete_project(self, pid: int) -> None:
        p = self.project(pid)
        self._exec("DELETE FROM projects WHERE id=?", (pid,))
        if p and p["workdir"]:
            wd = Path(p["workdir"])
            if wd.is_dir() and paths.projects_dir() in wd.parents:
                shutil.rmtree(wd, ignore_errors=True)

    # findings -------------------------------------------------------------
    def clear_findings(self, pid: int, stage: str | None = None) -> None:
        if stage:
            self._exec("DELETE FROM findings WHERE project_id=? AND stage=?", (pid, stage))
        else:
            self._exec("DELETE FROM findings WHERE project_id=?", (pid,))

    def add_findings(self, pid: int, items: Iterable[Finding]) -> int:
        rows = [
            (pid, f.stage, f.tool, f.kind, f.key, json.dumps(f.value, default=str),
             f.confidence.value if hasattr(f.confidence, "value") else str(f.confidence),
             f.provenance.value if hasattr(f.provenance, "value") else str(f.provenance),
             f.evidence, f.subject, json.dumps(f.extra, default=str))
            for f in items
        ]
        with self._lock:
            self._conn.executemany(
                "INSERT INTO findings(project_id,stage,tool,kind,key,value,confidence,provenance,evidence,subject,extra)"
                " VALUES(?,?,?,?,?,?,?,?,?,?,?)", rows)
            self._conn.commit()
        return len(rows)

    def findings(self, pid: int, stage: str | None = None, kind: str | None = None) -> list[dict]:
        sql, args = "SELECT * FROM findings WHERE project_id=?", [pid]
        if stage:
            sql += " AND stage=?"
            args.append(stage)
        if kind:
            sql += " AND kind=?"
            args.append(kind)
        out = self._all(sql + " ORDER BY id", args)
        for r in out:
            r["value"] = json.loads(r["value"])
            r["extra"] = json.loads(r["extra"] or "{}")
        return out

    # tool runs / artifacts --------------------------------------------------
    def log_tool_run(self, pid: int | None, tool: str, command: str, started: float, status: str, message: str = ""):
        self._exec("INSERT INTO tool_runs(project_id,tool,command,started,ended,status,message) VALUES(?,?,?,?,?,?,?)",
                   (pid, tool, command, started, time.time(), status, message[:4000]))

    def tool_runs(self, pid: int) -> list[dict]:
        return self._all("SELECT * FROM tool_runs WHERE project_id=? ORDER BY id", (pid,))

    def add_artifact(self, pid: int, rel_path: str, kind: str, size: int, sha256: str = "") -> None:
        self._exec("INSERT INTO artifacts(project_id,rel_path,kind,size,sha256) VALUES(?,?,?,?,?)",
                   (pid, rel_path, kind, size, sha256))

    def artifacts(self, pid: int) -> list[dict]:
        return self._all("SELECT * FROM artifacts WHERE project_id=? ORDER BY rel_path", (pid,))

    # settings ---------------------------------------------------------------
    def get_setting(self, key: str, default: Any = None) -> Any:
        rows = self._all("SELECT value FROM settings WHERE key=?", (key,))
        return json.loads(rows[0]["value"]) if rows else default

    def set_setting(self, key: str, value: Any) -> None:
        self._exec("INSERT INTO settings VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                   (key, json.dumps(value)))
