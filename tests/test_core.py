import shutil
import subprocess

import pytest

from reforge.analysis import binary, extract, identify, strings
from reforge.analysis.orchestrator import Orchestrator
from reforge.core.safety import Limits, UnsafeInput, run_tool, safe_member_path
from reforge.tools import registry


@pytest.mark.parametrize("key,fmt", [("apk", "apk"), ("jar", "jar"), ("wasm", "wasm"), ("asar", "asar")])
def test_identify(samples, key, fmt):
    assert identify.identify(samples[key]).fmt == fmt


def test_identify_native(samples):
    from conftest import NATIVE_FMT
    assert identify.identify(samples["native"]).fmt in NATIVE_FMT


def test_lief_native(samples):
    fs = binary.analyze(samples["native"])
    hdr = next(f.value for f in fs if f.key.endswith("header"))
    assert hdr["format"] in {"ELF", "PE", "MACHO"}
    assert any(f.key.endswith("libraries") and f.value for f in fs)


def test_identify_ignores_extension(tmp_path, samples):
    fake = tmp_path / "notes.txt"
    fake.write_bytes(samples["wasm"].read_bytes())
    assert identify.identify(fake).fmt == "wasm"


def test_macho_object(samples):
    if "macho" not in samples:
        pytest.skip("clang cannot target Mach-O here")
    assert identify.identify(samples["macho"]).fmt == "macho"
    hdr = next(f for f in binary.analyze(samples["macho"]) if f.key == "header").value
    assert hdr["arch"] == "ARM64" and hdr["format"] == "MACHO"


def test_lief_elf(samples):
    if "elf" not in samples:
        pytest.skip("ELF sample only on Linux")
    fs = {f.key: f.value for f in binary.analyze(samples["elf"])}
    assert fs["header"]["format"] == "ELF"
    assert fs["imported_functions"]["count"] > 0


def test_safe_member_path(tmp_path):
    assert safe_member_path(tmp_path, "a/b.txt") == (tmp_path / "a/b.txt").resolve()
    for bad in ("../x", "/etc/passwd", "a/../../x", "C:\\x", "..\\x"):
        with pytest.raises(UnsafeInput):
            safe_member_path(tmp_path, bad)


def test_zip_slip_blocked(tmp_path, samples):
    with pytest.raises(UnsafeInput):
        extract.extract_zip(samples["slip"], tmp_path / "o", Limits())
    assert not (tmp_path / "evil.txt").exists()


def test_zip_bomb_blocked(tmp_path, samples):
    with pytest.raises(UnsafeInput):
        extract.extract_zip(samples["bomb"], tmp_path / "o", Limits())


def test_file_count_limit(tmp_path, samples):
    with pytest.raises(UnsafeInput):
        extract.extract_zip(samples["apk"], tmp_path / "o", Limits(max_files=1))


def test_asar_extract(tmp_path, samples):
    res = extract.extract_asar(samples["asar"], tmp_path / "o", Limits())
    assert sorted(res.files) == ["main.js", "package.json", "src/ui/index.html"]
    assert b"telemetry" in (tmp_path / "o/main.js").read_bytes()


def test_strings_network(samples, tmp_path):
    p = tmp_path / "b.bin"
    p.write_bytes(b"\0\0https://api.example.com/v1/login\0\0" + "C:\\Program Files\\Demo".encode("utf-16le"))
    fs = {f.key: f.value for f in strings.analyze(p)}
    assert "https://api.example.com/v1/login" in fs["urls"]
    assert any("Program Files" in x for x in fs["windows_paths"])


def test_secrets_redacted(tmp_path):
    p = tmp_path / "s.bin"
    fake = "AK" + "IA" + "ABCDEFGHIJKLMNOP"   # assembled at runtime: dummy value, not a credential
    p.write_bytes(b"key=" + fake.encode() + b"\0")
    fs = {f.key: f.value for f in strings.analyze(p)}
    assert "AKIA" not in str(fs["possible_secrets"])


def test_run_tool_timeout_and_no_shell():
    import sys
    r = run_tool([sys.executable, "-c", "import time; time.sleep(5)"], timeout=1)
    assert r.timed_out and not r.ok
    r = run_tool([sys.executable, "-c", "import sys; print(sys.argv[1])", "$(id)"])
    assert r.stdout.strip() == "$(id)"


def test_run_tool_bounded_output():
    import sys
    r = run_tool([sys.executable, "-c", "import sys; sys.stdout.write('A' * 20000); sys.stdout.flush()"],
                 max_output=1024)
    assert r.truncated
    assert len(r.stdout) <= 1024


def test_registry_complete():
    reg = registry.load()
    assert len(reg) == 85 and [e["id"] for e in reg] == list(range(1, 86))
    sts = registry.all_status()
    lief = next(s for s in sts if s.entry["name"] == "LIEF")
    assert lief.status == registry.S_BUNDLED
    # nothing claims to be installed unless actually found
    for s in sts:
        if s.status == registry.S_INSTALLED:
            assert s.location


@pytest.mark.parametrize("key,profile", [("native", "standard"), ("apk", "standard"), ("asar", "standard"),
                                         ("jar", "deep"), ("wasm", "quick")])
def test_orchestrator_end_to_end(db, samples, key, profile):
    pid = db.create_project(key, str(samples[key]), profile)
    summary = Orchestrator(db).analyze(pid)
    assert db.project(pid)["status"] == "complete"
    rows = db.findings(pid)
    assert any(r["key"] == "format" for r in rows)
    assert any(r["kind"] == "feasibility" for r in rows)
    if key == "apk":
        techs = {r["key"] for r in rows if r["kind"] == "technology"}
        assert "Flutter" in techs
        assert any(r["key"] == "urls" and "https://api.example.com/v1/users" in r["value"] for r in rows)
    if key == "asar":
        pkg = next(r for r in rows if r["key"] == "package_json")
        assert pkg["value"]["version"] == "1.2.3"
    assert summary["format"] == identify.identify(samples[key]).fmt


def test_orchestrator_blocks_slip(db, samples):
    pid = db.create_project("slip", str(samples["slip"]), "standard")
    Orchestrator(db).analyze(pid)
    assert db.project(pid)["status"] == "blocked"


def test_report_export(db, samples, tmp_path):
    from reforge.analysis import report
    pid = db.create_project("native", str(samples["native"]), "standard")
    Orchestrator(db).analyze(pid)
    md = report.export(db, pid, tmp_path / "r.md").read_text()
    assert "## binary" in md and "lief" in md
    js = report.export(db, pid, tmp_path / "r.json").read_text()
    assert '"findings"' in js


def test_delete_project(db, samples):
    from pathlib import Path
    pid = db.create_project("x", str(samples["apk"]), "standard")
    Orchestrator(db).analyze(pid)
    wd = Path(db.project(pid)["workdir"])
    assert wd.exists()
    db.delete_project(pid)
    assert db.project(pid) is None and not wd.exists() and samples["apk"].exists()


# ---- integration tests: run only where the external tool is actually installed
@pytest.mark.skipif(not shutil.which("rabin2"), reason="radare2 not installed")
def test_radare2_adapter(db, samples):
    if "elf" not in samples:
        pytest.skip("ELF sample only on Linux")
    pid = db.create_project("elf", str(samples["elf"]), "standard")
    Orchestrator(db).analyze(pid)
    r = next(x for x in db.findings(pid, stage="tools") if x["tool"] == "radare2")
    assert r["value"]["info"]["bintype"] == "elf"


@pytest.mark.skipif(not (shutil.which("wat2wasm") and shutil.which("wasm-objdump")), reason="WABT not installed")
def test_wabt_adapter(db, tmp_path):
    wat = tmp_path / "m.wat"
    wat.write_text('(module (func (export "add") (param i32 i32) (result i32) local.get 0 local.get 1 i32.add))')
    wasm = tmp_path / "m.wasm"
    subprocess.run(["wat2wasm", str(wat), "-o", str(wasm)], check=True)
    pid = db.create_project("wasm", str(wasm), "standard")
    Orchestrator(db).analyze(pid)
    r = next(x for x in db.findings(pid, stage="tools") if x["tool"] == "wabt")
    assert "add" in str(r["value"])
