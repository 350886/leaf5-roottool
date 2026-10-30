# -*- mode: python ; coding: utf-8 -*-
from PyInstaller.utils.hooks import collect_submodules
from PyInstaller.utils.hooks import collect_all

datas = [('E:\\BOOX\\root-tool\\assets\\payload\\preload.so', 'assets/payload'), ('E:\\BOOX\\root-tool\\assets\\payload\\device_root.sh', 'assets/payload'), ('E:\\BOOX\\root-tool\\assets\\magisk\\Magisk-v31.1.apk', 'assets/magisk'), ('E:\\BOOX\\root-tool\\assets\\exploit_src\\exploit', 'assets/exploit_src/exploit')]
binaries = [('E:\\BOOX\\root-tool\\assets\\adb\\adb.exe', 'assets/adb'), ('E:\\BOOX\\root-tool\\assets\\adb\\AdbWinApi.dll', 'assets/adb'), ('E:\\BOOX\\root-tool\\assets\\adb\\AdbWinUsbApi.dll', 'assets/adb'), ('E:\\BOOX\\root-tool\\assets\\lito_op_n10_fhprg.bin', 'assets'), ('E:\\BOOX\\root-tool\\assets\\lito_moto_fhprg.bin', 'assets'), ('E:\\BOOX\\root-tool\\assets\\zadig.exe', 'assets')]
hiddenimports = ['adapter', 'adapter_ui', 'elfsyms', 'ndkman', 'fp', 'imageksym', 'edlman', 'a64', 'autopilot', 'gp', 'edlmain', 'edlclient', 'edllink', 'drivers', 'usbtrace', 'docopt', 'usb', 'serial', 'capstone', 'colorama']
hiddenimports += collect_submodules('edlclient')
tmp_ret = collect_all('libusb_package')
datas += tmp_ret[0]; binaries += tmp_ret[1]; hiddenimports += tmp_ret[2]


a = Analysis(
    ['E:\\BOOX\\root-tool\\roottool.py'],
    pathex=[],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['numpy', 'pandas', 'matplotlib', 'PIL', 'PyQt5', 'PySide6', 'scipy', 'setuptools', 'pip', 'pydoc_data', 'notebook', 'jupyter', 'IPython'],
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
    name='Leaf5RootTool',
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
    version='E:\\BOOX\\root-tool\\build\\version_info.txt',
)
