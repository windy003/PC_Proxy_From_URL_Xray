# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['P_xray_proxy.py'],
    pathex=[],
    binaries=[('tun2socks.exe', '.'), ('wintun.dll', '.')],
    datas=[('256x256.ico', '.'), ('icon.png', '.'), ('xray.exe', '.')],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
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
    name='proxyByUrl',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=['256x256.ico'],
)
