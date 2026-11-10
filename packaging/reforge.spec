# PyInstaller spec - builds the desktop app for the host OS.
# macOS: produces "Nexonic ReForge Studio.app" (packaged into DMG by packaging/macos/make_dmg.sh)
# Windows: produces dist/NexonicReForgeStudio/ (wrapped by packaging/windows/installer.iss)
import sys
from PyInstaller.utils.hooks import collect_data_files

datas = collect_data_files("reforge", includes=["tools/registry.json", "tools/packs.json", "tools/ghidra_scripts/*.java"])
hidden_mods = [
    "reforge.ui.main_window",
    "reforge.ui.highlighter",
    "reforge.ui.pages.main_pages",
    "reforge.ui.pages.explorer_page",
    "reforge.ui.pages.ui_explorer_page",
    "reforge.ui.pages.ai_page",
    "reforge.ui.pages.reconstruct_page",
    "reforge.ui.pages.workspace_page",
    "reforge.ui.pages.export_page",
    "reforge.ai",
    "reforge.ai.client",
    "reforge.ai.credentials",
    "reforge.ai.context",
    "reforge.reconstruct",
    "reforge.reconstruct.scaffold",
    "reforge.reconstruct.runner",
    "reforge.reconstruct.builder",
    "reforge.export",
    "reforge.export.exporter",
    "reforge.tools.adapters.apktool",
    "reforge.tools.adapters.binwalk",
    "reforge.tools.adapters.angr_adapter",
    "reforge.tools.adapters.assetripper",
    "reforge.tools.external",
    "reforge.tools.frida_bridge",
]
a = Analysis(["launch.py"], pathex=["../src"], datas=datas,
             hiddenimports=hidden_mods, excludes=["tkinter"], noarchive=False)
pyz = PYZ(a.pure)
exe = EXE(pyz, a.scripts, [], exclude_binaries=True, name="NexonicReForgeStudio", console=False,
          target_arch=None, codesign_identity=None, entitlements_file=None)
coll = COLLECT(exe, a.binaries, a.datas, name="NexonicReForgeStudio")
if sys.platform == "darwin":
    app = BUNDLE(coll, name="Nexonic ReForge Studio.app", bundle_identifier="com.nexonic.reforgestudio",
                 info_plist={"CFBundleShortVersionString": "0.9.0", "NSHighResolutionCapable": True,
                             "LSMinimumSystemVersion": "12.0", "NSHumanReadableCopyright": "Nexonic Technologies"})
