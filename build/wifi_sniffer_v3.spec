# -*- mode: python ; coding: utf-8 -*-

from pathlib import Path

from PyInstaller.utils.hooks import collect_submodules


project_root = Path.cwd()
spec_dir = project_root / "build"

datas = [
    (str(project_root / "templates"), "templates"),
    (str(project_root / "wifi_sniffer_v3" / "static"), "wifi_sniffer_v3/static"),
]

hiddenimports = []
hiddenimports += collect_submodules("engineio.async_drivers")
hiddenimports += collect_submodules("socketio")

a = Analysis(
    [str(project_root / "build" / "wifi_sniffer_launcher_v3.py")],
    pathex=[str(project_root)],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["IPython", "pytest", "matplotlib", "numpy", "tkinter"],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="WiFi_Sniffer_Control_Panel_v3",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    version=str(project_root / "build" / "assets" / "version_info_v3.txt"),
    icon=str(project_root / "build" / "assets" / "icon.ico"),
)
