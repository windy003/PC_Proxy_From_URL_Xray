# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['proxyByUrl.py'],
    pathex=[],
    binaries=[],
    datas=[('icon.png', '.'), ('xray.exe', '.')],
    hiddenimports=['PyQt5', 'PyQt5.QtGui', 'PyQt5.QtWidgets', 'PyQt5.QtCore', 'requests', 'json', 'base64', 'urllib3'],
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
    name='ProxyByUrl',
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
    icon=['icon.png'],
)
