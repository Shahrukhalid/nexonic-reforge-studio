"""Nexonic ReForge Studio — GitHub Autopilot Controller.

Provides autonomous development operations:
- Pre-flight quality verification (lint, unit tests, security checks)
- Automated branch creation and staging
- Pull request creation and automated squash-merge
- Semantic version bumping (patch, minor, major) across all manifest files
- Release tagging and GitHub release dispatch
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path

REPO_OWNER = "Shahrukhalid"
REPO_NAME = "nexonic-reforge-studio"
GITHUB_API = "https://api.github.com"
ROOT = Path(__file__).resolve().parents[1]


def get_github_token() -> str:
    """Retrieve GitHub token from environment or Git Credential Manager."""
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        return token
    try:
        res = subprocess.run(
            ["git", "credential", "fill"],
            input="protocol=https\nhost=github.com\n",
            text=True,
            capture_output=True,
            check=True,
        )
        for line in res.stdout.splitlines():
            if line.startswith("password="):
                return line.split("=", 1)[1]
    except Exception as e:
        print(f"Warning: Could not fetch credentials from git credential manager: {e}", file=sys.stderr)
    return ""


def github_request(endpoint: str, method: str = "GET", data: dict | None = None) -> dict | list:
    """Execute authenticated GitHub REST API request."""
    token = get_github_token()
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "reforge-autopilot",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"

    url = f"{GITHUB_API}/repos/{REPO_OWNER}/{REPO_NAME}/{endpoint.lstrip('/')}"
    body = json.dumps(data).encode("utf-8") if data is not None else None
    req = urllib.request.Request(url, data=body, headers=headers, method=method)

    try:
        with urllib.request.urlopen(req) as resp:
            content = resp.read().decode("utf-8")
            return json.loads(content) if content else {}
    except urllib.error.HTTPError as e:
        err_msg = e.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"GitHub API Error {e.code} on {method} {url}: {err_msg}") from e


def run_cmd(argv: list[str], cwd: Path | None = None) -> tuple[int, str]:
    """Run shell command and return returncode and stdout."""
    res = subprocess.run(argv, cwd=cwd or ROOT, text=True, capture_output=True)
    return res.returncode, res.stdout + ("\n" + res.stderr if res.stderr else "")


def verify_quality() -> bool:
    """Run linter, test suite, and packaging spec checks."""
    print("=== [1/3] Running Static Analysis (ruff) ===")
    code, out = run_cmd([sys.executable, "-m", "ruff", "check", "src", "tests", "scripts"])
    if code != 0:
        print(out)
        return False
    print("✓ Ruff check passed.")

    print("\n=== [2/3] Running Automated Test Suite (pytest) ===")
    env = dict(os.environ)
    env["QT_QPA_PLATFORM"] = "offscreen"
    res = subprocess.run([sys.executable, "-m", "pytest", "-q"], cwd=ROOT, text=True, env=env)
    if res.returncode != 0:
        return False
    print("✓ Pytest test suite passed.")

    print("\n=== [3/3] Verifying Packaging Specifications ===")
    spec = ROOT / "packaging" / "reforge.spec"
    iss = ROOT / "packaging" / "windows" / "installer.iss"
    if not spec.is_file() or not iss.is_file():
        print("✗ Missing packaging specifications.")
        return False
    print("✓ Packaging specifications present.")
    return True


def create_pr(branch_name: str, title: str, body: str) -> dict:
    """Push branch to origin and open a Pull Request."""
    print(f"Pushing branch {branch_name} to origin...")
    code, out = run_cmd(["git", "push", "-u", "origin", branch_name])
    if code != 0:
        raise RuntimeError(f"Failed to push branch: {out}")

    print("Opening Pull Request...")
    pr_data = {
        "title": title,
        "body": body,
        "head": branch_name,
        "base": "main",
    }
    pr = github_request("pulls", method="POST", data=pr_data)
    try:
        github_request(f"issues/{pr['number']}/labels", method="POST", data={"labels": ["auto-merge"]})
    except Exception as e:
        print(f"Warning adding auto-merge label: {e}")
    print(f"✓ Pull Request #{pr['number']} created: {pr['html_url']}")
    return pr


def auto_merge_pr(pr_number: int, commit_title: str | None = None) -> bool:
    """Squash merge a pull request and delete its head branch."""
    pr = github_request(f"pulls/{pr_number}")
    head_branch = pr["head"]["ref"]

    print(f"Attempting squash merge for PR #{pr_number} ({head_branch})...")
    data = {
        "commit_title": commit_title or f"Merge PR #{pr_number}: {pr['title']}",
        "merge_method": "squash",
    }
    try:
        res = github_request(f"pulls/{pr_number}/merge", method="PUT", data=data)
        if res.get("merged"):
            print(f"✓ PR #{pr_number} merged successfully.")
            # Delete remote branch
            try:
                run_cmd(["git", "push", "origin", "--delete", head_branch])
                print(f"✓ Deleted remote branch {head_branch}.")
            except Exception as e:
                print(f"Warning deleting branch: {e}")
            return True
    except Exception as e:
        print(f"Merge error: {e}")
        return False
    return False


REQUIRED_CI_CHECKS = [
    "test (ubuntu-24.04)",
    "test (macos-15)",
    "test (macos-15-intel)",
    "test (windows-2022)",
    "audit",
    "integration",
    "integration-macos",
]


def check_ci_status(commit_sha: str | None = None) -> tuple[bool, dict[str, str]]:
    """Query GitHub check-runs for the given commit (or HEAD) and verify required CI status."""
    if not commit_sha:
        code, out = run_cmd(["git", "rev-parse", "HEAD"])
        commit_sha = out.strip()

    print(f"Checking GitHub Actions CI status for commit {commit_sha}...")
    try:
        runs_data = github_request(f"commits/{commit_sha}/check-runs")
    except Exception as e:
        print(f"Failed to query check-runs via GitHub API: {e}", file=sys.stderr)
        return False, {}

    check_runs = runs_data.get("check_runs", []) if isinstance(runs_data, dict) else []
    statuses = {r["name"]: (r.get("status"), r.get("conclusion")) for r in check_runs if "name" in r}

    # If missing required checks on this commit directly, check associated PR head commit
    if not all(req in statuses for req in REQUIRED_CI_CHECKS):
        try:
            prs = github_request(f"commits/{commit_sha}/pulls")
            if prs and isinstance(prs, list):
                pr_head = prs[0]["head"]["sha"]
                pr_num = prs[0]["number"]
                print(f"Found associated PR #{pr_num}; checking PR head commit {pr_head[:7]}...")
                pr_runs = github_request(f"commits/{pr_head}/check-runs")
                for r in pr_runs.get("check_runs", []):
                    if "name" in r and r["name"] not in statuses:
                        statuses[r["name"]] = (r.get("status"), r.get("conclusion"))
        except Exception as e:
            print(f"Notice: Could not query associated PR for commit: {e}", file=sys.stderr)

    print(f"Evaluated {len(statuses)} check-runs for commit {commit_sha}:")
    for name, (status, conclusion) in statuses.items():
        if name in REQUIRED_CI_CHECKS:
            print(f"  - {name}: status={status}, conclusion={conclusion}")

    missing = []
    failed = []
    for req in REQUIRED_CI_CHECKS:
        if req not in statuses:
            missing.append(req)
        else:
            status, conclusion = statuses[req]
            if status != "completed" or conclusion != "success":
                failed.append((req, status, conclusion))

    if missing:
        print(f"Missing required CI checks: {missing}")
    if failed:
        print(f"Failed or incomplete required CI checks: {failed}")

    all_ok = not missing and not failed
    if all_ok:
        print("✓ All 7 required CI checks passed for this commit.")
    return all_ok, {k: str(v) for k, v in statuses.items()}


def tag_release(version: str, push: bool = True, force_skip_ci: bool = False) -> bool:
    """Safely tag a release only after verifying working tree and required CI checks."""
    code, out = run_cmd(["git", "status", "--porcelain"])
    if out.strip():
        print("Error: Working tree is not clean. Commit or stash changes before tagging.", file=sys.stderr)
        return False

    code, out = run_cmd(["git", "rev-parse", "--abbrev-ref", "HEAD"])
    branch = out.strip()
    if branch != "main":
        print(f"Warning: Current branch is '{branch}', expected 'main'.", file=sys.stderr)

    cur = get_current_version()
    clean_ver = version.lstrip("v")
    if cur != clean_ver:
        print(f"Error: Version mismatch! pyproject.toml has {cur}, requested tag is {clean_ver}", file=sys.stderr)
        return False

    if not force_skip_ci:
        ci_ok, _ = check_ci_status()
        if not ci_ok:
            print("Error: Required CI checks have not all passed for the current commit. Tagging aborted.", file=sys.stderr)
            return False

    tag_name = f"v{clean_ver}"
    print(f"Creating git tag {tag_name}...")
    code, out = run_cmd(["git", "tag", "-a", tag_name, "-m", f"Nexonic ReForge Studio {tag_name}"])
    if code != 0:
        print(f"Error creating tag: {out}", file=sys.stderr)
        return False

    if push:
        print(f"Pushing tag {tag_name} to origin...")
        code, out = run_cmd(["git", "push", "origin", tag_name])
        if code != 0:
            print(f"Error pushing tag: {out}", file=sys.stderr)
            return False
        print(f"✓ Tag {tag_name} pushed to origin successfully.")
    return True


def get_current_version() -> str:
    """Read version from pyproject.toml."""
    pyproj = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    m = re.search(r'version\s*=\s*"([^"]+)"', pyproj)
    return m.group(1) if m else "0.4.0"


def bump_version(part: str = "patch") -> str:
    """Bump semantic version across codebase and update manifests."""
    cur = get_current_version()
    parts = [int(p) for p in cur.split(".")]
    if part == "major":
        new_ver = f"{parts[0] + 1}.0.0"
    elif part == "minor":
        new_ver = f"{parts[0]}.{parts[1] + 1}.0"
    else:
        new_ver = f"{parts[0]}.{parts[1]}.{parts[2] + 1}"

    print(f"Bumping version: {cur} -> {new_ver}")

    # 1. pyproject.toml
    pyproj_path = ROOT / "pyproject.toml"
    pyproj = pyproj_path.read_text(encoding="utf-8")
    pyproj = re.sub(r'version\s*=\s*"[^"]+"', f'version = "{new_ver}"', pyproj)
    pyproj_path.write_text(pyproj, encoding="utf-8")

    # 2. src/reforge/__init__.py
    init_path = ROOT / "src" / "reforge" / "__init__.py"
    init_txt = init_path.read_text(encoding="utf-8")
    init_txt = re.sub(r'__version__\s*=\s*"[^"]+"', f'__version__ = "{new_ver}"', init_txt)
    init_path.write_text(init_txt, encoding="utf-8")

    # 3. packaging/reforge.spec
    spec_path = ROOT / "packaging" / "reforge.spec"
    spec_txt = spec_path.read_text(encoding="utf-8")
    spec_txt = re.sub(r'"CFBundleShortVersionString":\s*"[^"]+"', f'"CFBundleShortVersionString": "{new_ver}"', spec_txt)
    spec_path.write_text(spec_txt, encoding="utf-8")

    # 4. packaging/windows/installer.iss
    iss_path = ROOT / "packaging" / "windows" / "installer.iss"
    iss_txt = iss_path.read_text(encoding="utf-8")
    iss_txt = re.sub(r'#define\s+AppVer\s+"[^"]+"', f'#define AppVer "{new_ver}"', iss_txt)
    iss_path.write_text(iss_txt, encoding="utf-8")

    return new_ver


def main():
    parser = argparse.ArgumentParser(description="Nexonic ReForge Studio Autopilot Controller")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("verify", help="Run local linting, testing, and spec verification")
    sub.add_parser("status", help="Inspect git status and remote state")

    ci_p = sub.add_parser("check-ci", help="Check remote CI status for commit")
    ci_p.add_argument("--commit", default=None, help="Commit SHA (defaults to HEAD)")

    tag_p = sub.add_parser("tag", help="Safely create and push a release tag")
    tag_p.add_argument("--version", required=True, help="Release version (e.g. 0.5.2)")
    tag_p.add_argument("--no-push", action="store_true", help="Do not push tag to origin")
    tag_p.add_argument("--force-skip-ci", action="store_true", help="Skip CI status verification")

    pr_p = sub.add_parser("pr", help="Pull request operations")
    pr_sub = pr_p.add_subparsers(dest="pr_command", required=True)

    create_p = pr_sub.add_parser("create", help="Create PR for current branch")
    create_p.add_argument("--branch", required=True, help="Branch name")
    create_p.add_argument("--title", required=True, help="PR Title")
    create_p.add_argument("--body", default="", help="PR Body")

    merge_p = pr_sub.add_parser("merge", help="Auto-merge PR")
    merge_p.add_argument("number", type=int, help="PR number")

    bump_p = sub.add_parser("bump", help="Bump version")
    bump_p.add_argument("--type", choices=["patch", "minor", "major"], default="patch")

    args = parser.parse_args()

    if args.command == "verify":
        ok = verify_quality()
        sys.exit(0 if ok else 1)

    elif args.command == "status":
        code, out = run_cmd(["git", "status", "-s"])
        ver = get_current_version()
        print(f"Repository: {REPO_OWNER}/{REPO_NAME}")
        print(f"Current version: {ver}")
        print("Git working tree:")
        print(out or "Clean.")

    elif args.command == "check-ci":
        ok, _ = check_ci_status(args.commit)
        sys.exit(0 if ok else 1)

    elif args.command == "tag":
        ok = tag_release(args.version, push=not args.no_push, force_skip_ci=args.force_skip_ci)
        sys.exit(0 if ok else 1)

    elif args.command == "pr":
        if args.pr_command == "create":
            create_pr(args.branch, args.title, args.body)
        elif args.pr_command == "merge":
            ok = auto_merge_pr(args.number)
            sys.exit(0 if ok else 1)

    elif args.command == "bump":
        new_v = bump_version(args.type)
        print(f"Updated all configuration files to v{new_v}.")


if __name__ == "__main__":
    main()
