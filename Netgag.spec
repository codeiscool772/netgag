# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['main.py'],
    pathex=[],
    binaries=[
        ('netgag\\hooknet64.dll', 'netgag'),
        ('netgag\\nettest.exe', 'netgag'),
        ('netgag\\ifeo_stub.exe', 'netgag'),
    ],
    datas=[],
    hiddenimports=['netgag', 'netgag.auditlog', 'netgag.config', 'netgag.firewall',
                   'netgag.folderwatch', 'netgag.handlers', 'netgag.hooklog', 'netgag.ifeo',
                   'netgag.nethook', 'netgag.pathutil', 'netgag.procs', 'netgag.selftest', 'netgag.ui'],
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
    name='Netgag',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,  # UPX-packed exes trigger far more antivirus false positives
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    uac_admin=True,
)
