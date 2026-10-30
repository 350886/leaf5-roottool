#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
把 assets/ 下不随仓库走的二进制拉下来。

  python tools/fetch_deps.py            缺什么下什么
  python tools/fetch_deps.py --check    只检查，不下载
  python tools/fetch_deps.py --force    全部重下（已经有也覆盖）
  python tools/fetch_deps.py --no-zadig 跳过可选件
  python tools/fetch_deps.py --only adb 只处理某一项

全部走标准库，不依赖 requests。每项都带 sha256，下完即校验；校验不过
删文件报错，不留下一个"看起来在、其实是 404 页面"的坑。

preload.so 不在下载清单里 —— 它是编译产物，来源见 --check 时的提示。
"""

import argparse
import hashlib
import os
import shutil
import sys
import tempfile
import urllib.error
import urllib.request
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

UA = "leaf5-roottool-fetch/1.0 (+https://github.com/350886/leaf5-roottool)"
TIMEOUT = 60          # 单次连接超时
RETRIES = 3           # 断流重试次数，GitHub raw 偶尔抽风
CHUNK = 1 << 16       # 64KB，够快也不至于占内存


# ----------------------------------------------------------------------
# 清单
#
# kind:
#   file  —— 直接落盘
#   zip   —— 下 zip，从里面取 members 指定的几个文件
#
# sha 是"落地文件"的哈希，不是 zip 包的哈希。这样校验的是真正会被打进
# EXE 的那几个字节，而不是中间容器。
# ----------------------------------------------------------------------
DEPS = [
    dict(
        name="adb",
        kind="zip",
        url="https://dl.google.com/android/repository/platform-tools_r37.0.0-win.zip",
        # 固定 r37.0.0 而不是 -latest：latest 会漂移，哈希就对不上了。
        # r37.0.1 的三个文件与这里全都不同（实测），所以版本必须钉死。
        members={
            "platform-tools/adb.exe": ("assets/adb/adb.exe",
                                       "957e46b8615f7af5b7292a2ddabe98d2e61940c3fb2b0545756507f080613e71"),
            "platform-tools/AdbWinApi.dll": ("assets/adb/AdbWinApi.dll",
                                             "120bef587119c6cb926b86b9be90fdfbce38937588eae28cd91a94ce63c7b965"),
            "platform-tools/AdbWinUsbApi.dll": ("assets/adb/AdbWinUsbApi.dll",
                                                "6ca69a2ca0e31309c087d288f058977d421ad03500e4c3e1dbd981241a069c60"),
        },
        optional=False,
        note="Google platform-tools r37.0.0",
    ),
    dict(
        name="magisk",
        kind="file",
        url="https://github.com/topjohnwu/Magisk/releases/download/v31.1/Magisk-v31.1.apk",
        dest="assets/magisk/Magisk-v31.1.apk",
        sha="89cefac0a318afa39fb3880c45c87b036c05bc1ebf02a7a715b7f8d7c26ac6e7",
        optional=False,
        note="Magisk v31.1 官方 Release",
    ),
    dict(
        name="fhprg",
        kind="file",
        # bkerler/Loaders 是 edl 项目的 loader 合集，按厂商分目录。
        # 这一份的 sha256 与本地实测通过的那份逐字节相同（已核）。
        url=("https://raw.githubusercontent.com/bkerler/Loaders/main/"
             "oneplus/0013f0e100515198_2354228eebcbc203_fhprg_op_n10.bin"),
        dest="assets/lito_op_n10_fhprg.bin",
        sha="6558f49c3a55d0eb7fdd7bb326c9bb22b29f4b6b6316937e847e8b76e11f6ec0",
        optional=False,
        note="OnePlus N10 (SM6350/lito) firehose programmer，来自 bkerler/Loaders",
    ),
    dict(
        name="zadig",
        kind="file",
        # zadig.akeo.ie/downloads/ 已经 404，官方现在的下载点在 libwdi 的
        # Release 里。2.9 与仓库原先那份 5,256,264 字节的旧版不同，但功能一致。
        url="https://github.com/pbatard/libwdi/releases/download/v1.5.1/zadig-2.9.exe",
        dest="assets/zadig.exe",
        sha="4ecaa95df3da3621486a043aef8b3050b8bafe7c901402871e816229ef82039b",
        optional=True,
        note="Zadig 2.9（libwdi），只在缺 WinUSB 驱动时需要",
    ),
]

# 不进下载清单，但 --check 时会解释它从哪来
NOT_DOWNLOADABLE = [
    dict(
        path="assets/payload/preload.so",
        why="编译产物。两条路：① 有 root 的机器跑「内核适配向导」，"
            "它会取 kallsyms、生成 target.h、调 NDK 现编；"
            "② 没有 root 就用上面那个 programmer 进 9008，"
            "`--edl dump boot` 取镜像后反解。",
    ),
    dict(
        path="assets/lito_moto_fhprg.bin",
        why="可选备份。bkerler/Loaders 全库按 sha256 前 16 位搜过，没有这一份；"
            "它是 loader_candidates() 里排第二的兜底，缺了不影响 —— "
            "op_n10 那份排第一且实测通过。",
    ),
]


# ----------------------------------------------------------------------
# 工具函数
# ----------------------------------------------------------------------
def sha256_of(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(CHUNK), b""):
            h.update(b)
    return h.hexdigest()


def human(n):
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024.0


def download(url, out_path, label):
    """下到 out_path。失败重试 RETRIES 次，最后一次仍失败就抛。"""
    import time

    last = None
    for i in range(1, RETRIES + 1):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": UA})
            with urllib.request.urlopen(req, timeout=TIMEOUT) as r, open(out_path, "wb") as f:
                got = 0
                shown = 0.0
                t0 = time.monotonic()
                while True:
                    buf = r.read(CHUNK)
                    if not buf:
                        break
                    f.write(buf)
                    got += len(buf)
                    # 每 1MB 或每 0.5 秒才刷一行 —— 管道里 \r 不会回退，
                    # 逐块打会把日志刷成几千行
                    now = time.monotonic()
                    if got - shown >= (1 << 20) or now - t0 >= 0.5:
                        sys.stdout.write(f"\r    {label} {human(got)}   ")
                        sys.stdout.flush()
                        shown, t0 = got, now
                sys.stdout.write(f"\r    {label} {human(got)}   \n")
                sys.stdout.flush()
            return got
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError) as e:
            last = e
            sys.stdout.write(f"\r    {label} 第 {i}/{RETRIES} 次失败：{e}\n")
            if i < RETRIES:
                time.sleep(2 * i)      # 递增退避，别把远端打爆
    raise SystemExit(f"[-] 下载失败：{url}\n    {last}")


def place(src, dest_rel, want_sha):
    """把 src 落到仓库里的 dest_rel，校验哈希。返回 True 表示确实写了。"""
    dest = os.path.join(ROOT, dest_rel.replace("/", os.sep))
    os.makedirs(os.path.dirname(dest), exist_ok=True)

    got = sha256_of(src)
    if got != want_sha:
        raise SystemExit(
            f"[-] 哈希不符：{dest_rel}\n"
            f"    期望 {want_sha}\n"
            f"    实得 {got}\n"
            f"    远端可能换了内容，核对后更新 DEPS 里的 sha。")

    # 原子替换：先写同目录临时名再 rename，中断不会留半个文件
    tmp = dest + ".part"
    shutil.copyfile(src, tmp)
    os.replace(tmp, dest)
    return True


def need_fetch(dest_rel, want_sha, force):
    """已有的文件哈希对得上就跳过。"""
    dest = os.path.join(ROOT, dest_rel.replace("/", os.sep))
    if force or not os.path.isfile(dest):
        return True
    return sha256_of(dest) != want_sha


# ----------------------------------------------------------------------
# 单件处理
# ----------------------------------------------------------------------
def do_file(dep, force, check_only):
    dest = dep["dest"]
    if not need_fetch(dest, dep["sha"], force):
        print(f"  [=] {dest}  已就位")
        return 0
    if check_only:
        print(f"  [缺] {dest}  ← {dep['note']}")
        return 1

    print(f"  [>] {dest}")
    print(f"      {dep['url']}")
    with tempfile.TemporaryDirectory() as td:
        tmp = os.path.join(td, "dl.bin")
        n = download(dep["url"], tmp, dep["name"])
        place(tmp, dest, dep["sha"])
    print(f"      {human(n)}  OK")
    return 0


def do_zip(dep, force, check_only):
    todo = {m: (d, s) for m, (d, s) in dep["members"].items()
            if need_fetch(d, s, force)}
    if not todo:
        for d, _s in dep["members"].values():
            print(f"  [=] {d}  已就位")
        return 0
    if check_only:
        for d, _s in todo.values():
            print(f"  [缺] {d}  ← {dep['note']}")
        return len(todo)

    print(f"  [>] {dep['name']}")
    print(f"      {dep['url']}")
    with tempfile.TemporaryDirectory() as td:
        zp = os.path.join(td, "pkg.zip")
        n = download(dep["url"], zp, dep["name"])
        with zipfile.ZipFile(zp) as z:
            names = set(z.namelist())
            for member, (dest_rel, want) in todo.items():
                if member not in names:
                    raise SystemExit(f"[-] zip 里没有 {member}，包结构变了？")
                out = os.path.join(td, os.path.basename(member))
                with z.open(member) as src, open(out, "wb") as dst:
                    shutil.copyfileobj(src, dst, CHUNK)
                place(out, dest_rel, want)
                print(f"      → {dest_rel}")
    print(f"      {human(n)}  OK")
    return 0


# ----------------------------------------------------------------------
def main(argv=None):
    ap = argparse.ArgumentParser(
        description="拉取 assets/ 下不随仓库走的二进制（带 sha256 校验）")
    ap.add_argument("--check", action="store_true", help="只检查缺什么，不下载")
    ap.add_argument("--force", action="store_true", help="已有文件也重下")
    ap.add_argument("--no-zadig", action="store_true", help="跳过 zadig（可选件）")
    ap.add_argument("--only", default=None,
                    help="只处理某一项：" + "/".join(d["name"] for d in DEPS))
    args = ap.parse_args(argv)

    print(f"仓库根目录：{ROOT}")
    print()

    missing = 0
    for dep in DEPS:
        if args.only and dep["name"] != args.only:
            continue
        if args.no_zadig and dep["optional"]:
            print(f"  [-] {dep['name']}  已按 --no-zadig 跳过")
            continue
        fn = do_zip if dep["kind"] == "zip" else do_file
        missing += fn(dep, args.force, args.check)

    print()
    print("不随仓库走的其它文件：")
    for item in NOT_DOWNLOADABLE:
        p = os.path.join(ROOT, item["path"].replace("/", os.sep))
        state = "在" if os.path.isfile(p) else "缺"
        print(f"  [{state}] {item['path']}")
        if state == "缺":
            print(f"       {item['why']}")

    print()
    if missing:
        if args.check:
            print(f"还缺 {missing} 个文件。去掉 --check 再跑一次就会下。")
        else:
            print(f"有 {missing} 个没搞定，看上面的报错。")
        return 1
    print("必需的都在，可以 python build.py 了。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
