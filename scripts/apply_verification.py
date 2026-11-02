"""Apply GitHub repo metadata to registry.json.

Input JSON: {"owner/repo": "full_name|spdx|archived|pushed_yyyy-mm-dd" or "HTTP<code>"}
(the format produced by the browser/API helper; see docs/REGISTRY.md).
"""
import datetime as dt
import json
import sys
from pathlib import Path

REG = Path(__file__).resolve().parents[1] / "src" / "reforge" / "tools" / "registry.json"


def main(src: str, verified_on: str) -> None:
    data = json.loads(Path(src).read_text())
    reg = json.loads(REG.read_text())
    today = dt.date.fromisoformat(verified_on)
    n = 0
    for e in reg:
        slug = e["repo"].removeprefix("https://github.com/")
        v = data.get(slug)
        if not v:
            continue
        if v.startswith("HTTP"):
            if v == "HTTP404":
                e["verification"] = "failed"
                e["verification_error"] = v
            continue
        full, spdx, archived, pushed = v.split("|")
        e["canonical_repo"] = f"https://github.com/{full}"
        e["archived"] = archived == "true"
        e["last_push"] = pushed
        e["maintained"] = not e["archived"] and (today - dt.date.fromisoformat(pushed)).days < 365
        if spdx and spdx != "NOASSERTION":
            if spdx not in e["license"]:
                e["license_note"] = f"catalog said {e['license']}; GitHub detects {spdx}"
                e["license"] = spdx
        else:
            e["license_note"] = "GitHub could not classify the licence file; value from project docs, review manually"
        e["verification"] = "verified"
        e["verified_at"] = verified_on
        n += 1
    REG.write_text(json.dumps(reg, indent=1) + "\n")
    print(f"applied {n}; pending {sum(x['verification'] == 'pending' for x in reg)}")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else dt.date.today().isoformat())
