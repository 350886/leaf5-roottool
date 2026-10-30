#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
打包 Leaf5RootTool.exe

  python build.py            单文件（默认）
  python build.py --onedir   目录版，启动快，便于排障
  python build.py --sign     打包后签名

产物：dist/Leaf5RootTool.exe
"""

import os
import sys
import shutil
import subprocess

HERE = os.path.dirname(os.path.abspath(__file__))
NAME = "Leaf5RootTool"
VERSION = (1, 1, 3, 0)

ADB = ["adb.exe", "AdbWinApi.dll", "AdbWinUsbApi.dll"]
PAYLOAD = ["preload.so", "device_root.sh"]
MAGISK = ["Magisk-v31.1.apk"]
# firehose programmer：lito 平台。没有它 9008 通路直接断
LOADERS = ["lito_op_n10_fhprg.bin", "lito_moto_fhprg.bin"]
# Zadig（libwdi）：新机器缺 WinUSB 驱动时自动拉起
ZADIG = "zadig.exe"

# 适配向导要在用户机器上现编 preload.so，所以 exploit 源码必须跟着 EXE 走。
# 源仓库默认在相邻目录，可用 EXPLOIT_REPO 环境变量覆盖。
EXPLOIT_REPO = os.environ.get("EXPLOIT_REPO",
                              os.path.join(os.path.dirname(HERE),
                                           "leaf5-ghostlock", "exploit"))
SRC_DST = os.path.join(HERE, "assets", "exploit_src", "exploit")

# 只带走编译需要的东西，别把 out/ logs/ 一起塞进 EXE
SRC_SUBS = ("src", "assets")


def sync_exploit():
    """
    仓库 exploit/ → assets/exploit_src/exploit/。
    只镜像 src/、assets/、targets/onyx-leaf5/target.h；
    跳过 .bak*、out/、logs/、tests。
    """
    if not os.path.isdir(EXPLOIT_REPO):
        if os.path.isdir(SRC_DST):
            print(f"[!] 找不到 {EXPLOIT_REPO}，沿用上次同步的 {SRC_DST}")
            return SRC_DST
        raise SystemExit(f"[-] 找不到 exploit 源码：{EXPLOIT_REPO}")

    os.makedirs(SRC_DST, exist_ok=True)
    n = 0
    for sub in SRC_SUBS:
        s = os.path.join(EXPLOIT_REPO, sub)
        if not os.path.isdir(s):
            continue
        # 必须递归：src/kernelsnitch/ 这类子目录里的头文件是编译依赖
        for root, _dirs, files in os.walk(s):
            rel = os.path.relpath(root, s)
            d = os.path.join(SRC_DST, sub) if rel == "." else \
                os.path.join(SRC_DST, sub, rel)
            os.makedirs(d, exist_ok=True)
            for name in files:
                if ".bak" in name:
                    continue
                shutil.copyfile(os.path.join(root, name), os.path.join(d, name))
                n += 1

    th = os.path.join(EXPLOIT_REPO, "targets", "onyx-leaf5", "target.h")
    if os.path.isfile(th):
        td = os.path.join(SRC_DST, "targets", "onyx-leaf5")
        os.makedirs(td, exist_ok=True)
        shutil.copyfile(th, os.path.join(td, "target.h"))
        n += 1

    print(f"[*] 同步 exploit 源码 {n} 个文件 → {SRC_DST}")
    return SRC_DST


def ver_file():
    """PyInstaller 的版本资源，让 EXE 属性页有东西可看"""
    path = os.path.join(HERE, "build", "version_info.txt")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    # FixedFileInfo 要的是元组，StringFileInfo 要的是 "a.b.c.d"
    tup = "(" + ", ".join(str(x) for x in VERSION) + ")"
    txt = ".".join(str(x) for x in VERSION)
    with open(path, "w", encoding="utf-8") as f:
        f.write(
            "VSVersionInfo(\n"
            "  ffi=FixedFileInfo(filevers=" + tup + ", prodvers=" + tup + ",\n"
            "    mask=0x3f, flags=0x0, OS=0x40004, fileType=0x1, subtype=0x0, date=(0,0)),\n"
            "  kids=[\n"
            "    StringFileInfo([StringTable('080404b0', [\n"
            "      StringStruct('CompanyName', 'local'),\n"
            "      StringStruct('FileDescription', 'Leaf5 Root Tool'),\n"
            "      StringStruct('FileVersion', '" + txt + "'),\n"
            "      StringStruct('InternalName', 'Leaf5RootTool'),\n"
            "      StringStruct('OriginalFilename', 'Leaf5RootTool.exe'),\n"
            "      StringStruct('ProductName', 'Leaf5 Root Tool'),\n"
            "      StringStruct('ProductVersion', '" + txt + "')])]),\n"
            "    VarFileInfo([VarStruct('Translation', [2052, 1200])])\n"
            "  ]\n"
            ")\n"
        )
    return path


def main():
    onedir = "--onedir" in sys.argv
    do_sign = "--sign" in sys.argv

    # 解释器自检：本工具是 tkinter GUI，打包用的解释器没有 tkinter 时
    # PyInstaller 不会失败，会安安静静打出一个 24MB 的坏包 ——
    # 双击启动直接 ModuleNotFoundError，而且从体积上看不出来（只比正常包小 3.4MB）。
    # 实测踩过一次，所以这里硬拦。
    try:
        import tkinter  # noqa: F401
    except Exception:
        print("[x] 当前解释器没有 tkinter，打出来的 EXE 会一启动就崩。")
        print(f"    正在用的是 {sys.executable}")
        print("    换一个有 tkinter 的 64 位 Python：")
        print(r'      "C:\Users\%USERNAME%\AppData\Local\Programs\Python\Python312\python.exe" build.py --sign')
        return 4

    # edl 现在是库化在进程内跑，这几个包必须真的能 import 才能打包
    try:
        import usb  # noqa: F401
        import docopt  # noqa: F401
        import libusb_package  # noqa: F401
    except Exception as e:
        print("[x] 缺 edl 依赖：", e)
        print("    pip install pyusb pyserial libusb-package docopt")
        return 4

    missing = []
    for n in ADB:
        p = os.path.join(HERE, "assets", "adb", n)
        if not os.path.isfile(p):
            missing.append(p)
    for n in PAYLOAD:
        p = os.path.join(HERE, "assets", "payload", n)
        if not os.path.isfile(p):
            missing.append(p)
    for n in MAGISK:
        p = os.path.join(HERE, "assets", "magisk", n)
        if not os.path.isfile(p):
            missing.append(p)
    # 只要求第一个 loader 在（第二个是可选的同平台备份）
    p = os.path.join(HERE, "assets", LOADERS[0])
    if not os.path.isfile(p):
        missing.append(p)
    for d in ("edlclient",):
        if not os.path.isdir(os.path.join(HERE, d)):
            missing.append(os.path.join(HERE, d))
    if not os.path.isfile(os.path.join(HERE, "edlmain.py")):
        missing.append(os.path.join(HERE, "edlmain.py"))
    if missing:
        print("[-] 缺文件：")
        for m in missing:
            print("    ", m)
        print()
        # 分两类提示：能自动下的、只能自己产的。混在一起说，新手会去翻固件包
        fetchable = [m for m in missing
                     if not m.endswith("preload.so")
                     and os.path.basename(m) not in ("edlclient", "edlmain.py")]
        if fetchable:
            print("    第三方二进制不进仓库，一条命令拉齐（带 sha256 校验）：")
            print("        python tools/fetch_deps.py")
        if any(m.endswith("preload.so") for m in missing):
            print("    preload.so 是编译产物，不在拉取清单里 —— 跑一次「内核适配向导」现编。")
        return 2

    src_dir = sync_exploit()

    args = [
        sys.executable, "-m", "PyInstaller",
        "--noconfirm", "--clean",
        "--onedir" if onedir else "--onefile",
        "--windowed",
        "--name", NAME,
        "--version-file", ver_file(),
        "--distpath", os.path.join(HERE, "dist"),
        "--workpath", os.path.join(HERE, "build", "work"),
        "--specpath", os.path.join(HERE, "build"),
    ]

    icon = os.path.join(HERE, "assets", "icon.ico")
    if os.path.isfile(icon):
        args += ["--icon", icon]

    for n in ADB:
        args += ["--add-binary", f"{os.path.join(HERE,'assets','adb',n)};assets/adb"]
    for n in PAYLOAD:
        args += ["--add-data", f"{os.path.join(HERE,'assets','payload',n)};assets/payload"]
    for n in MAGISK:
        args += ["--add-data", f"{os.path.join(HERE,'assets','magisk',n)};assets/magisk"]
    # programmer 和 zadig 都是二进制，放 assets 根（edllink/drivers 按名字找）
    for n in LOADERS:
        p = os.path.join(HERE, "assets", n)
        if os.path.isfile(p):
            args += ["--add-binary", f"{p};assets"]
    zp = os.path.join(HERE, "assets", ZADIG)
    if os.path.isfile(zp):
        args += ["--add-binary", f"{zp};assets"]

    # 适配向导用的源码树（现编 preload.so 需要）
    args += ["--add-data", f"{src_dir};assets/exploit_src/exploit"]
    # edlclient 的子模块大量是条件导入，静态分析跟不全 —— 整包收
    args += ["--collect-submodules", "edlclient"]
    # libusb-1.0.dll 跟着 libusb_package 走；不 collect 的话运行期
    # add_dll_directory 会落空，pyusb 报 "No backend available"
    args += ["--collect-all", "libusb_package"]
    for mod in ("adapter", "adapter_ui", "elfsyms", "ndkman", "fp",
                "imageksym", "edlman", "a64", "autopilot",
                "edlmain", "edlclient", "edllink", "drivers", "usbtrace",
                "docopt", "usb", "serial", "capstone", "colorama"):
        args += ["--hidden-import", mod]

    # 砍掉没用到的大件，能省 8MB 左右
    for mod in ("numpy", "pandas", "matplotlib", "PIL", "PyQt5", "PySide6",
                "scipy", "setuptools", "pip", "pydoc_data",
                "notebook", "jupyter", "IPython"):
        args += ["--exclude-module", mod]

    args.append(os.path.join(HERE, "roottool.py"))

    print("[*] 打包中…")
    r = subprocess.run(args, cwd=HERE)
    if r.returncode != 0:
        print("[-] PyInstaller 失败")
        return r.returncode

    exe = os.path.join(HERE, "dist", NAME + ".exe")
    if not os.path.isfile(exe):
        print(f"[-] 没生成 {exe}")
        return 3
    size = os.path.getsize(exe) / 1048576
    print(f"[+] {exe}  {size:.1f} MB")

    if do_sign:
        rc = sign(exe)
        if rc != 0:
            print("[!] 签名失败，EXE 仍然可用（只是没有数字签名）")
    return 0


def sign(exe):
    """用本机已有的代码签名证书签一下。找不到就跳过。"""
    candidates = [
        r"C:\Program Files (x86)\Windows Kits\10\bin\10.0.22621.0\x64\signtool.exe",
        r"C:\Program Files (x86)\Windows Kits\10\bin\10.0.19041.0\x64\signtool.exe",
    ]
    signtool = next((p for p in candidates if os.path.isfile(p)), None)
    if not signtool:
        found = shutil.which("signtool")
        signtool = found
    if not signtool:
        print("[!] 没找到 signtool，跳过签名")
        return 1

    # 先找带私钥的代码签名证书
    ps = ("Get-ChildItem Cert:\\CurrentUser\\My -CodeSigningCert | "
          "Where-Object { $_.HasPrivateKey } | Select-Object -First 1 -ExpandProperty Thumbprint")
    try:
        p = subprocess.run(["powershell", "-NoProfile", "-Command", ps],
                           capture_output=True, text=True, timeout=60)
        thumb = (p.stdout or "").strip()
    except Exception:
        thumb = ""
    if not thumb:
        print("[!] 当前用户证书库没有代码签名证书，跳过签名")
        return 1

    # 用 PowerShell 调，避免 Git Bash 把 /sha1 /fd 这类参数当路径转换
    cmd = (f"& '{signtool}' sign /sha1 {thumb} /fd SHA256 /tr http://timestamp.digicert.com "
           f"/td SHA256 '{exe}'")
    r = subprocess.run(["powershell", "-NoProfile", "-Command", cmd],
                       capture_output=True, text=True, timeout=180)
    print(r.stdout.strip() or r.stderr.strip())
    if r.returncode == 0:
        print("[+] 已签名")
    return r.returncode


if __name__ == "__main__":
    sys.exit(main())
