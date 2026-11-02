"""Verify registry entries against the GitHub API (license, archived, last push).

Usage:  GITHUB_TOKEN=... python scripts/verify_registry.py
Updates registry.json in place: verification -> "verified" | "failed".
"""
import datetime as dt
import json
import os
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

REG = Path(__file__).resolve().parents[1] / "src" / "reforge" / "tools" / "registry.json"


def gh(path: str) -> dict:
    req = urllib.request.Request(f"https://api.github.com{path}", headers={"Accept": "application/vnd.github+json"})
    tok = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if tok:
        req.add_header("Authorization", f"Bearer {tok}")
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.load(r)


def main() -> int:
    reg = json.loads(REG.read_text())
    now = dt.datetime.now(dt.UTC)
    ok = fail = 0
    for e in reg:
        if e["verification"] == "verified" and "--force" not in sys.argv:
            continue
        slug = e["repo"].removeprefix("https://github.com/")
        try:
            d = gh(f"/repos/{slug}")
        except urllib.error.HTTPError as err:
            if err.code == 403:
                print("rate limited - stop; rerun later or set GITHUB_TOKEN")
                break
            e["verification"] = "failed"
            e["verification_error"] = f"HTTP {err.code}"
            fail += 1
            continue
        spdx = (d.get("license") or {}).get("spdx_id")
        if spdx and spdx != "NOASSERTION":
            if e["license"] not in ("unknown",) and spdx not in e["license"]:
                e["license_note"] = f"catalog said {e['license']}; GitHub reports {spdx}"
            e["license"] = spdx if e["license"] == "unknown" or spdx not in e["license"] else e["license"]
        e["canonical_repo"] = d.get("html_url")
        e["archived"] = d.get("archived")
        e["last_push"] = d.get("pushed_at")
        age = (now - dt.datetime.fromisoformat(d["pushed_at"].replace("Z", "+00:00"))).days
        e["maintained"] = (not d.get("archived")) and age < 365
        e["verification"] = "verified"
        e["verified_at"] = now.isoformat(timespec="seconds")
        ok += 1
        time.sleep(0.2)
    REG.write_text(json.dumps(reg, indent=1) + "\n")
    print(f"verified={ok} failed={fail} pending={sum(e['verification'] == 'pending' for e in reg)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
