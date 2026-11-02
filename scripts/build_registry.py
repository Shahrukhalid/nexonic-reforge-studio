"""Generate src/reforge/tools/registry.json from the compact catalog below.

License / maintenance fields are *initial* values and are marked
`verification: "pending"` until scripts/verify_registry.py confirms them
against the GitHub API.  Run:  python scripts/build_registry.py
"""
import json
from pathlib import Path

ALL = ["macos", "windows", "linux"]
MW = ["macos", "linux"]
W = ["windows"]
L = ["linux"]

# id, name, repo, category, kind, platforms, license, integration, detect, priority, notes
# kind: cli | library | gui | plugin | server | mcp | resource | model
# integration: python-lib | cli-adapter | external-app | plugin-host | reference-only | paid-host
# detect: "bin:<exe>[|<exe>]" or "py:<module>" or "" (manual / not detectable)
C = [
 (1, "Ghidra", "NationalSecurityAgency/ghidra", "core", "gui", ALL, "Apache-2.0", "cli-adapter", "bin:analyzeHeadless", 1, "Headless analysis + ReForgeExport.java (functions, call graph, decompilation); requires JDK 21+. Tool pack: ghidra"),
 (2, "radare2", "radareorg/radare2", "core", "cli", ALL, "LGPL-3.0", "cli-adapter", "bin:rabin2|r2", 1, ""),
 (3, "Frida", "frida/frida", "core", "library", ALL, "wxWindows-3.1", "python-lib", "py:frida", 2, "Dynamic instrumentation: only inside an approved isolated runtime"),
 (4, "x64dbg", "x64dbg/x64dbg", "core", "gui", W, "GPL-3.0", "external-app", "bin:x64dbg|x96dbg", 3, "Windows-only GUI debugger; launched externally"),
 (5, "Cutter", "rizinorg/cutter", "core", "gui", ALL, "GPL-3.0", "external-app", "bin:cutter|Cutter", 3, "GUI front-end for Rizin"),
 (6, "Rizin", "rizinorg/rizin", "core", "cli", ALL, "LGPL-3.0", "cli-adapter", "bin:rz-bin|rizin", 1, ""),
 (7, "ImHex", "WerWolv/ImHex", "core", "gui", ALL, "GPL-2.0", "external-app", "bin:imhex", 3, "Open file in external hex editor"),
 (8, "JADX", "skylot/jadx", "core", "cli", ALL, "Apache-2.0", "cli-adapter", "bin:jadx", 1, "Requires JRE 11+"),
 (9, "ILSpy", "icsharpcode/ILSpy", "core", "cli", ALL, "MIT", "cli-adapter", "bin:ilspycmd", 1, "ilspycmd (.NET global tool) is cross-platform; GUI is Windows/Avalonia"),
 (10, "dnSpyEx", "dnSpyEx/dnSpy", "core", "gui", W, "GPL-3.0", "external-app", "bin:dnSpy", 3, "Windows-only GUI"),
 (11, "Apktool", "iBotPeaches/Apktool", "core", "cli", ALL, "Apache-2.0", "cli-adapter", "bin:apktool", 1, "Requires JRE"),
 (12, "MobSF", "MobSF/Mobile-Security-Framework-MobSF", "core", "server", ALL, "GPL-3.0", "external-app", "", 3, "REST API against a user-run MobSF server"),
 (13, "angr", "angr/angr", "core", "library", ALL, "BSD-2-Clause", "python-lib", "py:angr", 2, "Large dependency set; optional pack"),
 (14, "Detect It Easy", "horsicq/Detect-It-Easy", "core", "cli", ALL, "MIT", "cli-adapter", "bin:diec", 1, "diec -j JSON output"),
 (15, "LIEF", "lief-project/LIEF", "core", "library", ALL, "Apache-2.0", "python-lib", "py:lief", 1, "Bundled core engine"),
 (16, "ipsw", "blacktop/ipsw", "apple", "cli", ALL, "MIT", "cli-adapter", "bin:ipsw", 2, ""),
 (17, "LLDB scripts (DerekSelander)", "DerekSelander/LLDB", "apple", "plugin", ["macos"], "unknown", "plugin-host", "", 4, "LLDB python scripts; debugging only in isolated runtime"),
 (18, "pymobiledevice3", "doronz88/pymobiledevice3", "apple", "library", ALL, "GPL-3.0", "python-lib", "py:pymobiledevice3", 3, "Talks to user's own iOS device"),
 (19, "objection", "sensepost/objection", "apple", "cli", ALL, "GPL-3.0", "cli-adapter", "bin:objection", 4, "Runtime mobile exploration (Frida-based); isolated device only"),
 (20, "class-dump", "nygard/class-dump", "apple", "cli", ["macos"], "unknown", "cli-adapter", "bin:class-dump", 4, "Unmaintained; no Swift / modern arm64e support"),
 (21, "LLVM / LLDB", "llvm/llvm-project", "apple", "cli", ALL, "Apache-2.0 WITH LLVM-exception", "cli-adapter", "bin:llvm-objdump|lldb", 2, "llvm-objdump for disassembly; lldb only in isolated runtime"),
 (22, "pwndbg", "pwndbg/pwndbg", "native", "plugin", MW, "MIT", "plugin-host", "", 4, "GDB/LLDB plugin"),
 (23, "GEF", "hugsy/gef", "native", "plugin", L, "MIT", "plugin-host", "", 4, "GDB plugin; Linux"),
 (24, "rr", "rr-debugger/rr", "native", "cli", L, "MIT", "cli-adapter", "bin:rr", 4, "Linux-only record/replay; needs perf counters"),
 (25, "edb-debugger", "eteran/edb-debugger", "native", "gui", L, "GPL-2.0", "external-app", "bin:edb", 4, "Linux GUI debugger"),
 (26, "Volatility 3", "volatilityfoundation/volatility3", "native", "cli", ALL, "VSL-1.0", "cli-adapter", "bin:vol|vol.py", 4, "Memory-image forensics; Volatility Software License"),
 (27, "PE-sieve", "hasherezade/pe-sieve", "native", "cli", W, "BSD-2-Clause", "cli-adapter", "bin:pe-sieve64|pe-sieve", 4, "Scans live processes - Windows only"),
 (28, "BinDiff", "google/bindiff", "native", "cli", ALL, "Apache-2.0", "cli-adapter", "bin:bindiff", 3, "Consumes BinExport files"),
 (29, "BinExport", "google/binexport", "native", "plugin", ALL, "Apache-2.0", "plugin-host", "", 3, "Ghidra/IDA/Binary Ninja exporter plugin"),
 (30, "Diaphora", "joxeankoret/diaphora", "native", "plugin", ALL, "AGPL-3.0", "plugin-host", "", 4, "IDA plugin (Ghidra support experimental); AGPL"),
 (31, "Capstone", "capstone-engine/capstone", "native", "library", ALL, "BSD-3-Clause", "python-lib", "py:capstone", 1, "Disassembly engine"),
 (32, "Keystone", "keystone-engine/keystone", "native", "library", ALL, "GPL-2.0", "python-lib", "py:keystone", 4, "Assembler; low maintenance activity"),
 (33, "Androguard", "androguard/androguard", "android", "library", ALL, "Apache-2.0", "python-lib", "py:androguard", 1, ""),
 (34, "Recaf", "Col-E/Recaf", "android", "gui", ALL, "MIT", "external-app", "", 3, "Java bytecode editor GUI"),
 (35, "Bytecode Viewer", "Konloch/bytecode-viewer", "android", "gui", ALL, "GPL-3.0", "external-app", "", 4, ""),
 (36, "Vineflower", "Vineflower/vineflower", "android", "cli", ALL, "Apache-2.0", "cli-adapter", "bin:vineflower", 1, "Java decompiler jar"),
 (37, "Medusa", "Ch0pin/medusa", "android", "cli", ALL, "GPL-3.0", "cli-adapter", "", 4, "Frida-based dynamic analysis; isolated device only"),
 (38, "dex2jar", "pxb1988/dex2jar", "android", "cli", ALL, "Apache-2.0", "cli-adapter", "bin:d2j-dex2jar|d2j-dex2jar.sh", 4, "Low maintenance; JADX preferred"),
 (39, "pyinstxtractor", "extremecoders-re/pyinstxtractor", "unpack", "cli", ALL, "GPL-3.0", "cli-adapter", "bin:pyinstxtractor", 2, "Single script; GPL - optional download"),
 (40, "pycdc (Decompyle++)", "zrax/pycdc", "unpack", "cli", ALL, "GPL-3.0", "cli-adapter", "bin:pycdc", 2, "Partial support for newer Python versions"),
 (41, "Electron ASAR", "electron/asar", "unpack", "cli", ALL, "MIT", "python-lib", "builtin", 1, "Format parsed natively by ReForge (no Node needed)"),
 (42, "GoReSym", "mandiant/GoReSym", "unpack", "cli", ALL, "MIT", "cli-adapter", "bin:GoReSym", 2, ""),
 (43, "blutter", "worawit/blutter", "unpack", "cli", ALL, "unknown", "cli-adapter", "", 3, "Flutter arm64 AOT; builds Dart runtime per version"),
 (44, "hermes-dec", "P1sec/hermes-dec", "unpack", "cli", ALL, "unknown", "cli-adapter", "bin:hbc-decompiler", 3, ""),
 (45, "WABT", "WebAssembly/wabt", "unpack", "cli", ALL, "Apache-2.0", "cli-adapter", "bin:wasm-objdump|wasm2wat", 1, ""),
 (46, "GDRE Tools", "GDRETools/gdsdecomp", "unpack", "cli", ALL, "MIT", "cli-adapter", "bin:gdre_tools", 3, "Godot projects"),
 (47, "Il2CppDumper", "Perfare/Il2CppDumper", "unpack", "cli", ALL, "MIT", "cli-adapter", "bin:Il2CppDumper", 2, ".NET; archived/low activity - Cpp2IL preferred"),
 (48, "Cpp2IL", "SamboyCoding/Cpp2IL", "unpack", "cli", ALL, "MIT", "cli-adapter", "bin:Cpp2IL", 2, ""),
 (49, "AssetRipper", "AssetRipper/AssetRipper", "games", "gui", ALL, "GPL-3.0", "external-app", "bin:AssetRipper.GUI.Free", 3, "Only for assets the user is authorized to extract"),
 (50, "UEViewer (umodel)", "gildor2/UEViewer", "games", "cli", ["windows", "linux"], "custom", "external-app", "bin:umodel", 4, "GitHub detects MIT, but the README states its own terms - review before bundling"),
 (51, "FModel", "4sval/FModel", "games", "gui", W, "GPL-3.0", "external-app", "", 4, "Windows-only"),
 (52, "r2unity", "radareorg/r2unity", "games", "plugin", ALL, "unknown", "plugin-host", "", 5, "radare2 plugin for Unity metadata"),
 (53, "Unity game hacking resources", "imadr/Unity-game-hacking", "games", "resource", ALL, "n/a", "reference-only", "", 5, "Documentation list, not an executable tool"),
 (54, "mitmproxy", "mitmproxy/mitmproxy", "network", "cli", ALL, "MIT", "cli-adapter", "bin:mitmdump", 3, "Only with user consent in an isolated runtime"),
 (55, "mitmproxy2swagger", "alufers/mitmproxy2swagger", "network", "cli", ALL, "MIT", "cli-adapter", "bin:mitmproxy2swagger", 3, "Builds OpenAPI from captured flows"),
 (56, "webcrack", "j4k0xb/webcrack", "network", "cli", ALL, "MIT", "cli-adapter", "bin:webcrack", 2, "Node.js tool"),
 (57, "Wireshark / tshark", "wireshark/wireshark", "network", "cli", ALL, "GPL-2.0", "cli-adapter", "bin:tshark", 3, ""),
 (58, "Scapy", "secdev/scapy", "network", "library", ALL, "GPL-2.0", "python-lib", "py:scapy", 4, ""),
 (59, "OWASP ZAP", "zaproxy/zaproxy", "network", "server", ALL, "Apache-2.0", "external-app", "bin:zap.sh|zap", 5, "Web-app scanner; only against systems the user is authorized to test"),
 (60, "Kaitai Struct", "kaitai-io/kaitai_struct", "network", "cli", ALL, "GPL-3.0 (compiler) / MIT (runtimes)", "cli-adapter", "bin:kaitai-struct-compiler", 3, ""),
 (61, "capa", "mandiant/capa", "advanced", "cli", ALL, "Apache-2.0", "cli-adapter", "bin:capa", 1, "Capability detection; capa -j"),
 (62, "FLOSS", "mandiant/flare-floss", "advanced", "cli", ALL, "Apache-2.0", "cli-adapter", "bin:floss", 2, "Obfuscated string recovery (emulation, PE-focused)"),
 (63, "YARA-X", "VirusTotal/yara-x", "advanced", "library", ALL, "BSD-3-Clause", "python-lib", "py:yara_x", 2, ""),
 (64, "Unicorn", "unicorn-engine/unicorn", "advanced", "library", ALL, "GPL-2.0", "python-lib", "py:unicorn", 3, "CPU emulator (no host execution)"),
 (65, "Qiling", "qilingframework/qiling", "advanced", "library", ALL, "GPL-2.0", "python-lib", "py:qiling", 4, ""),
 (66, "DynamoRIO", "DynamoRIO/dynamorio", "advanced", "cli", ["windows", "linux"], "BSD-3-Clause", "cli-adapter", "bin:drrun", 5, "Executes the target - isolated runtime only; no macOS support"),
 (67, "Triton", "JonathanSalwan/Triton", "advanced", "library", ALL, "Apache-2.0", "python-lib", "py:triton", 4, ""),
 (68, "Miasm", "cea-sec/miasm", "advanced", "library", ALL, "GPL-2.0", "python-lib", "py:miasm", 4, ""),
 (69, "angr-management", "angr/angr-management", "advanced", "gui", ALL, "BSD-2-Clause", "external-app", "bin:angr-management", 5, ""),
 (70, "QBDI", "QBDI/QBDI", "advanced", "library", ALL, "Apache-2.0", "python-lib", "py:pyqbdi", 5, "Executes the target - isolated runtime only"),
 (71, "Ghidra MCP Server (bethington)", "bethington/ghidra-mcp", "ai", "mcp", ALL, "unknown", "plugin-host", "", 3, "Ghidra plugin + MCP bridge; bind to localhost only"),
 (72, "GhidraMCP", "LaurieWired/GhidraMCP", "ai", "mcp", ALL, "Apache-2.0", "plugin-host", "", 3, "Bind to localhost only"),
 (73, "JADX AI MCP", "zinja-coder/jadx-ai-mcp", "ai", "mcp", ALL, "unknown", "plugin-host", "", 3, "JADX-GUI plugin"),
 (74, "radare2 MCP", "radareorg/radare2-mcp", "ai", "mcp", ALL, "unknown", "cli-adapter", "bin:r2mcp", 3, ""),
 (75, "r2ai", "radareorg/r2ai", "ai", "plugin", ALL, "MIT", "plugin-host", "", 4, ""),
 (76, "GhidrAssist", "symgraph/GhidrAssist", "ai", "plugin", ALL, "unknown", "plugin-host", "", 4, "Ghidra plugin"),
 (77, "LLM4Decompile", "albertan017/LLM4Decompile", "ai", "model", ALL, "unknown", "reference-only", "", 4, "Research model weights; local GPU inference"),
 (78, "Gepetto", "JusticeRage/Gepetto", "ai", "plugin", ALL, "GPL-3.0", "paid-host", "", 5, "IDA Pro plugin - requires paid IDA"),
 (79, "IDA Pro MCP", "mrexodia/ida-pro-mcp", "ai", "mcp", ALL, "MIT", "paid-host", "", 5, "Requires paid IDA Pro"),
 (80, "Official IDA MCP", "HexRaysSA/ida-mcp", "ai", "mcp", ALL, "unknown", "paid-host", "", 5, "Requires paid IDA Pro"),
 (81, "Binwalk", "ReFirmLabs/binwalk", "firmware", "cli", ALL, "MIT", "cli-adapter", "bin:binwalk", 2, "v3 is Rust-based"),
 (82, "unblob", "onekey-sec/unblob", "firmware", "cli", MW, "MIT", "cli-adapter", "bin:unblob", 2, "No native Windows support"),
 (83, "UEFITool", "LongSoft/UEFITool", "firmware", "cli", ALL, "BSD-2-Clause", "cli-adapter", "bin:UEFIExtract", 4, ""),
 (84, "EMBA", "e-m-b-a/emba", "firmware", "cli", L, "GPL-3.0", "external-app", "", 5, "Linux-only, Docker-based"),
 (85, "OFRAK", "redballoonsecurity/ofrak", "firmware", "library", MW, "RBS Community License", "python-lib", "py:ofrak", 5, "Licence restricts commercial use - optional, not bundled"),
]

out = []
for (i, name, repo, cat, kind, plats, lic, integ, det, prio, notes) in C:
    out.append({"id": i, "name": name, "repo": f"https://github.com/{repo}", "category": cat, "kind": kind,
                "platforms": plats, "license": lic, "integration": integ, "detect": det, "priority": prio,
                "notes": notes, "verification": "pending", "maintained": None, "archived": None,
                "last_push": None})
assert len(out) == 85 and len({o["repo"] for o in out}) == 85
dst = Path(__file__).resolve().parents[1] / "src" / "reforge" / "tools" / "registry.json"
KEEP = ("verification", "maintained", "archived", "last_push", "verified_at", "canonical_repo",
        "license_note", "verification_error")
if dst.exists():
    old = {o["id"]: o for o in json.loads(dst.read_text())}
    for o in out:
        prev = old.get(o["id"])
        if prev and prev.get("repo") == o["repo"] and prev.get("verification") != "pending":
            for k in KEEP:
                if k in prev:
                    o[k] = prev[k]
            if "license_note" in prev:
                o["license"] = prev["license"]
dst.write_text(json.dumps(out, indent=1) + "\n")
print(f"wrote {len(out)} entries -> {dst}")
