# -*- mode: python ; coding: utf-8 -*-

block_cipher = None

a = Analysis(
    ['main.py'],
    pathex=[],
    binaries=[],
    datas=[
        ('database/schema.sql', 'database'),
        ('.env.example', '.'),
    ],
    hiddenimports=[
        'customtkinter',
        'cryptography',
        'watchdog',
        'psutil',
        'matplotlib',
        'pandas',
        'reportlab',
        'database.db_manager',
        'dashboard.dashboard_tab',
        'dashboard.encrypt_tab',
        'dashboard.logs_tab',
        'dashboard.report_tab',
        'dashboard.settings_tab',
        'dashboard.pdf_generator',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludedimports=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='BlueTeamSystem',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)