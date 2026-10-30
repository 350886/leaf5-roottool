# -*- coding: utf-8 -*-
"""
ndkman.py — Android NDK 的查找 / 下载 / 解压 / 校验 / 裁剪。

为什么要这个：
  preload.so 必须用 NDK 的 aarch64-linux-android35-clang 交叉编译。
  目标机器是普通 Windows，大概率没装 Android SDK。所以工具要能自己拉一份。

体积账（r29 windows）：
  zip  ~700 MB    解压后 ~3.6 GB    裁剪后 ~1.6 GB
  裁剪只删"跟 aarch64 编译无关"的目录（sources/、另两个平台的 prebuilt、
  python-packages/、simpleperf/ 等），bin/ 下一个文件都不动 —— 动了会踩
  DLL 依赖的坑，而且难恢复。
"""

import os
import shutil
import ssl
import subprocess
import sys
import urllib.request
import urllib.error
import zipfile

# ── 可选的 NDK 下载源。按顺序试，第一个成功就停 ──────────────────────
NDK_CANDIDATES = [
    ("r29", "https://dl.google.com/android/repository/android-ndk-r29-windows.zip",
     "android-ndk-r29", "android-ndk-r29-windows.zip"),
    ("r27c", "https://dl.google.com/android/repository/android-ndk-r27c-windows.zip",
     "android-ndk-r27c", "android-ndk-r27c-windows.zip"),
]

# 编译只需要这个 target（Android 13 = API 33，用 35 的 sysroot 向下兼容）
TARGET_API = "35"
HOST_TAG = "windows-x86_64"

# 裁剪时整目录删掉的东西（跟编译无关，删了不影响 clang）
TRIM_DIRS = [
    "sources",
    "python-packages",
    "simpleperf",
    "shader-tools",
    "docs",
    "meta",
    "ndk-build",
    "build",
    "wrap.sh",
    "CHANGELOG.md",
    "NOTICE",
    "NOTICE.toolchain",
    "source.properties",
]


class NdkError(Exception):
    pass


# ----------------------------------------------------------------------
# 查找
# ----------------------------------------------------------------------
def _clang_in(ndk_root):
    """ndk_root 下有可用的 aarch64 clang 就返回其 .cmd 路径，否则 None"""
    p = os.path.join(ndk_root, "toolchains", "llvm", "prebuilt", HOST_TAG,
                     "bin", f"aarch64-linux-android{TARGET_API}-clang.cmd")
    if os.path.isfile(p):
        return p
    # 有些老 NDK 只有不带 .cmd 的 shell 包装（Git Bash 下可执行）
    p2 = p[:-4]
    if os.path.isfile(p2):
        return p2
    return None


def _sdk_roots():
    """列出可能存在的 Android SDK 根目录"""
    roots = []
    for env in ("ANDROID_HOME", "ANDROID_SDK_ROOT"):
        v = os.environ.get(env)
        if v and os.path.isdir(v):
            roots.append(v)
    la = os.environ.get("LOCALAPPDATA", "")
    if la:
        roots.append(os.path.join(la, "Android", "Sdk"))
    up = os.environ.get("USERPROFILE", "")
    if up:
        roots.append(os.path.join(up, "AppData", "Local", "Android", "Sdk"))
        # Unity / UE 自带的 SDK
        roots.append(os.path.join(up, "AppData", "Local", "Android", "Sdk"))
    # 本工具自己下载的
    roots.append(os.path.join(os.environ.get("LOCALAPPDATA", os.path.expanduser("~")),
                              "Leaf5RootTool", "ndk"))
    return [r for r in roots if r and os.path.isdir(r)]


def find_installed(log=None):
    """
    返回 (ndk_root, clang_path) 或 (None, None)。
    优先级：环境变量声明的 SDK → LOCALAPPDATA 下的 SDK → 本工具自建目录。
    """
    def say(s):
        if log:
            log(s)

    seen = set()
    for sdk in _sdk_roots():
        ndkroot = os.path.join(sdk, "ndk")
        cands = []
        if os.path.isdir(ndkroot):
            cands = [os.path.join(ndkroot, v) for v in sorted(
                os.listdir(ndkroot), reverse=True)]
        # 工具自建目录是 ndk/<版本号 或 rXX>
        cands.append(sdk)
        for c in cands:
            if not os.path.isdir(c) or c in seen:
                continue
            seen.add(c)
            cc = _clang_in(c)
            if cc:
                say(f"  发现 NDK：{c}")
                return c, cc
    return None, None


# ----------------------------------------------------------------------
# 下载
# ----------------------------------------------------------------------
def _human(n):
    for u in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.1f}{u}"
        n /= 1024.0
    return f"{n:.1f}TB"


def download(url, dest, progress=None, cancel=None, timeout=60):
    """
    断点续传下载。progress(done, total) 每 256KB 回调一次。
    dest 是最终文件；临时文件为 dest + ".part"。
    """
    part = dest + ".part"
    os.makedirs(os.path.dirname(dest), exist_ok=True)

    have = os.path.getsize(part) if os.path.isfile(part) else 0
    req = urllib.request.Request(url, headers={
        "User-Agent": "Leaf5RootTool/1.0",
        "Accept": "*/*",
    })
    if have:
        req.add_header("Range", f"bytes={have}-")

    # 公司网络常见的自签证书场景，这里不降级校验，只给明确报错
    ctx = ssl.create_default_context()

    try:
        resp = urllib.request.urlopen(req, timeout=timeout, context=ctx)
    except urllib.error.HTTPError as e:
        if e.code == 416:                     # Range 超出，说明 .part 已完整
            os.replace(part, dest)
            return dest
        raise NdkError(f"下载失败 HTTP {e.code}：{url}")

    total = 0
    clen = resp.headers.get("Content-Length")
    crange = resp.headers.get("Content-Range")
    if crange and "/" in crange:
        try:
            total = int(crange.split("/")[-1])
        except ValueError:
            total = 0
    elif clen:
        try:
            total = int(clen) + (have if resp.status == 206 else 0)
        except ValueError:
            total = 0

    mode = "ab" if (have and resp.status == 206) else "wb"
    if mode == "wb":
        have = 0

    done = have
    last_tick = 0
    with open(part, mode) as f:
        while True:
            if cancel and cancel():
                raise NdkError("已取消")
            chunk = resp.read(262144)
            if not chunk:
                break
            f.write(chunk)
            done += len(chunk)
            if progress and done - last_tick >= 262144:
                progress(done, total)
                last_tick = done
    if progress:
        progress(done, total)

    if total and done < total:
        raise NdkError(f"下载不完整：{_human(done)} / {_human(total)}，"
                       f"保留 .part 可重试续传")
    os.replace(part, dest)
    return dest


# ----------------------------------------------------------------------
# 解压
# ----------------------------------------------------------------------
def extract(zip_path, dest_root, progress=None, cancel=None):
    """
    解压到 dest_root，返回真正的 NDK 根（zip 里有一层 android-ndk-rXX）。
    """
    os.makedirs(dest_root, exist_ok=True)
    try:
        zf = zipfile.ZipFile(zip_path)
    except zipfile.BadZipFile:
        raise NdkError("下载到的不是合法 zip，可能被代理/网关替换了内容。"
                       "删掉 .part 和 zip 重下")

    members = zf.infolist()
    total = len(members)
    top = None
    for m in members:
        name = m.filename.replace("\\", "/")
        if "/" in name:
            top = name.split("/")[0]
            break
    if not top:
        raise NdkError("zip 结构异常：找不到顶层目录")

    for i, m in enumerate(members):
        if cancel and cancel():
            raise NdkError("已取消")
        # 防 zip slip
        name = m.filename.replace("\\", "/")
        if name.startswith("/") or ".." in name.split("/"):
            continue
        zf.extract(m, dest_root)
        if progress and (i % 200 == 0 or i == total - 1):
            progress(i + 1, total)
    zf.close()

    ndk_root = os.path.join(dest_root, top)
    # zip 里顶层目录名可能是 android-ndk-r29，我们统一放到 dest_root 下
    if os.path.isdir(ndk_root):
        return ndk_root
    return dest_root


# ----------------------------------------------------------------------
# 校验
# ----------------------------------------------------------------------
def verify(ndk_root, log=None):
    """跑一次 clang --version，确认工具链能启动（DLL 齐全）"""
    cc = _clang_in(ndk_root)
    if not cc:
        raise NdkError(f"NDK 目录里找不到 aarch64-linux-android{TARGET_API}-clang：{ndk_root}")

    def run(args):
        flags = 0
        if os.name == "nt":
            flags = 0x08000000       # CREATE_NO_WINDOW
        return subprocess.run(
            args, capture_output=True, timeout=120, creationflags=flags,
            cwd=os.path.dirname(cc) or None)

    # .cmd 在 Windows 上必须经过 cmd.exe；直接 CreateProcess 会失败
    if cc.lower().endswith(".cmd"):
        args = ["cmd", "/c", cc, "--version"]
    else:
        args = [cc, "--version"]

    try:
        r = run(args)
    except Exception as e:
        raise NdkError(f"clang 启动失败：{e}")

    out = (r.stdout or b"").decode("utf-8", "replace")
    err = (r.stderr or b"").decode("utf-8", "replace")
    if "clang version" not in out:
        raise NdkError(f"clang 不能正常工作。stdout={out[:300]} stderr={err[:300]}")
    ver = out.strip().splitlines()[0]
    if log:
        log(f"  {ver}")
    return cc


def probe_compile(cc, workdir, log=None):
    """
    真编一个空 .so，确认 sysroot/linker 都齐。
    比 --version 有力：--version 只证明 exe 能起，不证明能链接。
    """
    os.makedirs(workdir, exist_ok=True)
    src = os.path.join(workdir, "_probe.c")
    out = os.path.join(workdir, "_probe.so")
    with open(src, "w", encoding="utf-8") as f:
        f.write("int leaf5_probe(void){return 42;}\n")

    sysroot = os.path.join(os.path.dirname(os.path.dirname(cc)),
                           "sysroot")
    args = [cc, f"--target=aarch64-linux-android{TARGET_API}",
            f"--sysroot={sysroot}", "-O2", "-fPIC", "-shared",
            src, "-o", out]
    if cc.lower().endswith(".cmd"):
        args = ["cmd", "/c"] + args

    flags = 0x08000000 if os.name == "nt" else 0
    r = subprocess.run(args, capture_output=True, timeout=180,
                       creationflags=flags,
                       cwd=os.path.dirname(cc) or None)
    if r.returncode != 0 or not os.path.isfile(out):
        err = (r.stderr or b"").decode("utf-8", "replace")
        raise NdkError(f"试编译失败：{err[:500]}")
    size = os.path.getsize(out)
    if log:
        log(f"  试编译通过：_probe.so {size} 字节")
    for p in (src, out):
        try:
            os.remove(p)
        except OSError:
            pass
    return True


# ----------------------------------------------------------------------
# 裁剪
# ----------------------------------------------------------------------
def _dir_size(path):
    n = 0
    for root, _dirs, files in os.walk(path):
        for f in files:
            try:
                n += os.path.getsize(os.path.join(root, f))
            except OSError:
                pass
    return n


def trim(ndk_root, log=None, cancel=None):
    """
    删掉跟 aarch64 编译无关的目录。bin/ 一律不动。
    返回省下的字节数。
    """
    def say(s):
        if log:
            log(s)

    saved = 0
    targets = []

    for d in TRIM_DIRS:
        p = os.path.join(ndk_root, d)
        if os.path.exists(p):
            targets.append(p)

    prebuilt = os.path.join(ndk_root, "toolchains", "llvm", "prebuilt")
    if os.path.isdir(prebuilt):
        for name in os.listdir(prebuilt):
            if name != HOST_TAG:
                targets.append(os.path.join(prebuilt, name))

    for p in targets:
        if cancel and cancel():
            break
        try:
            if os.path.isdir(p):
                sz = _dir_size(p)
                shutil.rmtree(p, ignore_errors=True)
            else:
                sz = os.path.getsize(p)
                os.remove(p)
            if not os.path.exists(p):
                saved += sz
                say(f"  删除 {os.path.basename(p):<28} {_human(sz)}")
        except Exception as e:
            say(f"  [跳过] {p}: {e}")
    return saved


def total_size(ndk_root):
    return _dir_size(ndk_root)


# ----------------------------------------------------------------------
# 一站式安装
# ----------------------------------------------------------------------
def install(dest_root=None, progress=None, log=None, cancel=None,
            auto_trim=True):
    """
    查找已有 NDK；没有就下载 + 解压 + 校验 + 裁剪。
    返回 (ndk_root, clang_path)。
    progress 是 dict 回调：{"phase": str, "done": int, "total": int}
    """
    def say(s):
        if log:
            log(s)

    def ph(phase):
        if progress:
            progress({"phase": phase, "done": 0, "total": 0})

    def dl(done, total):
        if progress:
            progress({"phase": "下载 NDK", "done": done, "total": total})

    def ex(done, total):
        if progress:
            progress({"phase": "解压 NDK", "done": done, "total": total})

    say("检查本机是否已有 NDK…")
    root, cc = find_installed(log=log)
    if root:
        try:
            verify(root, log=log)
            say("  已有 NDK 可用，不重复下载")
            return root, cc
        except NdkError as e:
            say(f"  找到的 NDK 不可用（{e}），改走下载")

    if dest_root is None:
        dest_root = os.path.join(
            os.environ.get("LOCALAPPDATA", os.path.expanduser("~")),
            "Leaf5RootTool", "ndk")

    # 磁盘空间：解压约需要 4 GB
    try:
        free = shutil.disk_usage(os.path.dirname(dest_root) or ".").free
        if free < 5 * 1024 ** 3:
            say(f"  [!] 目标盘剩余 {_human(free)}，NDK 解压约需 4 GB")
    except OSError:
        pass

    last_err = None
    for tag, url, topname, fname in NDK_CANDIDATES:
        if cancel and cancel():
            raise NdkError("已取消")
        zpath = os.path.join(dest_root, fname)
        final_dir = os.path.join(dest_root, tag)

        if os.path.isdir(final_dir) and _clang_in(final_dir):
            say(f"  复用已下载的 {tag}")
            try:
                cc = verify(final_dir, log=log)
                return final_dir, cc
            except NdkError:
                pass

        if not os.path.isfile(zpath):
            say(f"下载 NDK {tag}（约 700 MB）…")
            say(f"  源 {url}")
            try:
                download(url, zpath, progress=dl, cancel=cancel)
            except Exception as e:
                last_err = e
                say(f"  下载失败：{e}")
                continue
            say(f"  下载完成 {_human(os.path.getsize(zpath))}")

        ph("解压 NDK")
        say("解压中（约 3.6 GB，几分钟）…")
        try:
            got = extract(zpath, dest_root, progress=ex, cancel=cancel)
        except Exception as e:
            last_err = e
            say(f"  解压失败：{e}")
            continue

        # zip 顶层目录名可能不是 tag，统一成 tag
        if got != final_dir:
            if os.path.isdir(final_dir):
                shutil.rmtree(final_dir, ignore_errors=True)
            try:
                os.replace(got, final_dir)
            except OSError:
                shutil.move(got, final_dir)

        try:
            cc = verify(final_dir, log=log)
        except NdkError as e:
            last_err = e
            say(f"  校验失败：{e}")
            continue

        ph("试编译")
        try:
            probe_compile(cc, os.path.join(dest_root, "_probe"))
        except NdkError as e:
            last_err = e
            say(f"  {e}")
            continue

        if auto_trim:
            ph("裁剪 NDK")
            before = total_size(final_dir)
            say(f"裁剪无关目录（当前 {_human(before)}）…")
            saved = trim(final_dir, log=log, cancel=cancel)
            after = total_size(final_dir)
            say(f"  裁剪完成 {_human(after)}（省 {_human(saved)}）")
            # 裁完必须再试一次编，否则等于把工具链裁坏了还不知道
            try:
                probe_compile(cc, os.path.join(dest_root, "_probe"))
                cc = verify(final_dir, log=log)
            except NdkError as e:
                raise NdkError(
                    f"裁剪后工具链损坏（{e}）。请删掉 {final_dir} 重新运行安装。")

        try:
            os.remove(zpath)
            say("  已删除 zip 安装包")
        except OSError:
            pass
        return final_dir, cc

    raise NdkError(f"所有下载源都失败：{last_err}")


if __name__ == "__main__":
    # 命令行自测：python ndkman.py [--dest DIR] [--no-trim]
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--dest", default=None)
    ap.add_argument("--no-trim", action="store_true")
    a = ap.parse_args()

    def _p(info):
        if info["total"]:
            pct = info["done"] * 100.0 / info["total"]
            sys.stdout.write(f"\r{info['phase']}: {pct:5.1f}%  "
                             f"{_human(info['done'])}/{_human(info['total'])}   ")
        else:
            sys.stdout.write(f"\r{info['phase']}…   ")
        sys.stdout.flush()

    root, cc = install(dest_root=a.dest, progress=_p, log=print,
                       auto_trim=not a.no_trim)
    print()
    print(f"OK  root={root}")
    print(f"    clang={cc}")
