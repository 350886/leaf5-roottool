# -*- coding: utf-8 -*-
"""
adapter.py — 把 GhostLock exploit 适配到"另一版内核"的整套流水线。

流程：
   boot.img ──切 kernel 段──> 解压 ──> vmlinux.elf
                                        │
                                        ├─ 提符号偏移（自动）
                                        └─ 生成 targets/<id>/target.h
                                                 │
                                                 ├─ 结构体/栈常量 → 人工填
                                                 └─ 三阶段编译 → preload.so

能自动的：60 个符号偏移、target.h 骨架、编译、产物登记
不能自动的：TASK_CRED_OFF / WAITER_LOCAL_OFF / PRCTL_WAITER_WORD_DEFAULT /
           PRCTL_FRAME_TOTAL —— 结构体布局与栈帧大小，符号表里没有，
           必须反汇编锚点或 panic 定标（见 MIGRATION 说明）

已验证的编译参数（在本机 NDK 27.0.12077973 上产出 md5
6f36e1e889e0d05aa2fd9d93f3771168，与出厂载荷逐字节一致）。
"""

import bz2
import gzip
import hashlib
import io
import json
import lzma
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import time
import zlib

import elfsyms

# ----------------------------------------------------------------------
# 常量
# ----------------------------------------------------------------------
BOOT_MAGIC = b"ANDROID!"
TARGET_API = "35"

# 这些宏符号表里有，能自动算 —— 实际列表由 elfsyms.discover_macros()
# 从模板里现场扫出来，这里不再维护硬编码表。

# 这些宏符号表里没有，需要人工
MANUAL_MACROS = [
    ("WAITER_LOCAL_OFF",            "rt_mutex_waiter 里 task 字段的偏移。"
                                    "本机 0x50，主线 4.19 是 0x40（本机多了 prio+deadline）"),
    ("TASK_CRED_OFF",               "task_struct.cred 的偏移。看 commit_creds 里 "
                                    "ldr x8,[x19,#0x7e0] 那个立即数"),
    ("PRCTL_FRAME_TOTAL",           "__arm64_sys_prctl 的总帧大小。看函数开头的 "
                                    "stp/sub sp 指令"),
    ("PRCTL_WAITER_WORD_DEFAULT",   "copy word 的下标，决定从栈上哪个槽读 waiter。"
                                    "必须 panic 定标：PRCTL_POISON=1 跑一次，从 x21 反推"),
]

# 生成文件里用来标记"还没填"的记号。编译前会检查它，留着就拒绝编译。
FILL_MARK = "/*FILL_ME*/"

# 解压魔数 → 算法名
MAGICS = [
    (b"\x1f\x8b\x08", "gzip"),
    (b"\xfd7zXZ\x00", "xz"),
    (b"\x5d\x00\x00\x80", "lzma"),
    (b"\x5d\x00\x00\x00", "lzma"),
    (b"\x02\x21\x4c\x18", "lz4legacy"),
    (b"\x04\x22\x4d\x18", "lz4frame"),
    (b"\x28\xb5\x2f\xfd", "zstd"),
    (b"BZh", "bzip2"),
    (b"\x89LZO\x00\r\n\x1a\n", "lzo"),
]


class AdapterError(Exception):
    pass


# ----------------------------------------------------------------------
# boot 镜像
# ----------------------------------------------------------------------
def parse_boot_hdr(path):
    """解析 ANDROID! 头。返回 {magic,kernel,ramdisk,size,hdr_ver} 或 None"""
    try:
        with open(path, "rb") as f:
            d = f.read(0x1000)
    except OSError:
        return None
    if len(d) < 64 or d[:8] != BOOT_MAGIC:
        return None
    kernel_size, = struct.unpack("<I", d[8:12])
    ramdisk_size, = struct.unpack("<I", d[16:20])
    hdr_ver, = struct.unpack("<I", d[0x28:0x2C])
    page = 2048 if hdr_ver < 2 else 4096
    total = page + ((kernel_size + ramdisk_size + page - 1) // page) * page
    return {"magic": True, "kernel": kernel_size, "ramdisk": ramdisk_size,
            "page": page, "size": total, "hdr_ver": hdr_ver}


def slice_kernel(path, out_path=None):
    """从 boot.img 里切出 kernel 段的原始字节（未解压）"""
    h = parse_boot_hdr(path)
    if not h:
        raise AdapterError("不是合法的 Android boot 镜像（缺 ANDROID! 魔数）")
    with open(path, "rb") as f:
        f.seek(h["page"])
        blob = f.read(h["kernel"])
    if len(blob) != h["kernel"]:
        raise AdapterError(f"kernel 段被截断：读到 {len(blob)}，头里写 {h['kernel']}")
    if out_path:
        with open(out_path, "wb") as f:
            f.write(blob)
    return blob


# ----------------------------------------------------------------------
# 解压
# ----------------------------------------------------------------------
def _gunzip(blob):
    """处理多 member 的 gzip（内核镜像是单个，但别假设）"""
    out = bytearray()
    while blob:
        d = zlib.decompressobj(16 + zlib.MAX_WBITS)
        try:
            out += d.decompress(blob)
            out += d.flush()
        except zlib.error:
            break
        blob = d.unused_data
        if not blob.startswith(b"\x1f\x8b"):
            break
    return bytes(out)


def _lz4_block(src):
    """解一个 raw LZ4 block"""
    out = bytearray()
    i, n = 0, len(src)
    while i < n:
        token = src[i]
        i += 1
        lit = token >> 4
        if lit == 15:
            while i < n:
                b = src[i]
                i += 1
                lit += b
                if b != 255:
                    break
        out += src[i:i + lit]
        i += lit
        if i >= n:
            break
        off = src[i] | (src[i + 1] << 8)
        i += 2
        ml = token & 0x0F
        if ml == 15:
            while i < n:
                b = src[i]
                i += 1
                ml += b
                if b != 255:
                    break
        ml += 4
        start = len(out) - off
        if start < 0:
            raise AdapterError("LZ4 数据损坏（回溯越界）")
        for k in range(ml):
            out.append(out[start + k])
    return bytes(out)


def _lz4_legacy(blob):
    """legacy frame：magic(4) + blocksize(4)，之后每块 4 字节长度 + raw block"""
    pos = 8
    out = bytearray()
    while pos + 4 <= len(blob):
        n, = struct.unpack("<I", blob[pos:pos + 4])
        pos += 4
        if n == 0 or pos + n > len(blob):
            break
        out += _lz4_block(blob[pos:pos + n])
        pos += n
    return bytes(out)


def _dec(kind, stream):
    """按算法解一段流。失败抛异常，由调用方换下一个候选位置"""
    if kind == "gzip":
        return _gunzip(stream)
    if kind == "xz":
        return lzma.decompress(stream, format=lzma.FORMAT_XZ)
    if kind == "lzma":
        return lzma.decompress(stream, format=lzma.FORMAT_ALONE)
    if kind == "bzip2":
        return bz2.decompress(stream)
    if kind == "lz4legacy":
        return _lz4_legacy(stream)
    if kind == "lz4frame":
        try:
            import lz4.frame
        except ImportError:
            raise AdapterError("kernel 是 LZ4 frame 压缩，需要 lz4 模块。"
                               "执行：pip install lz4")
        return lz4.frame.decompress(stream)
    if kind == "zstd":
        try:
            import zstandard
        except ImportError:
            raise AdapterError("kernel 是 zstd 压缩，需要 zstandard 模块。"
                               "执行：pip install zstandard")
        return zstandard.ZstdDecompressor().decompress(stream)
    if kind == "lzo":
        raise AdapterError("kernel 是 LZO 压缩，没有纯 Python 解压器。"
                           "用 `lzop -d` 手工解，或换用固件包里自带的 vmlinux")
    raise AdapterError(f"未知压缩算法 {kind}")


def _looks_like_arm64_image(blob):
    """ARM64 Image：偏移 0x38 处是 "ARM\\x64" 魔数"""
    return len(blob) > 0x40 and blob[0x38:0x3C] == b"ARM\x64"


def _image_hint():
    return ("这是**未压缩的 ARM64 Image**，没有 ELF 头。符号表（kallsyms）是编译进"
            ".rodata 的，工具能现场反解出全部符号名和偏移，不需要 root、"
            "也不需要任何外部文件。直接把 boot.img 或这个 Image 拖进向导即可。")


def decompress_kernel(blob):
    """
    返回 (解压后字节, "算法@偏移")。

    为什么不是"找到第一个魔数就解"：未压缩的 kernel 里随机数据撞上
    gzip 魔数（1f 8b 08）很常见，直接解会得到空或垃圾。所以每个算法
    往后试多个候选位置，解出来必须真的是 ELF 才认。
    """
    if blob[:4] == b"\x7fELF":
        return blob, "none"
    if _looks_like_arm64_image(blob):
        # 裸 Image 本身就是可用原料：kallsyms 的 token 表和偏移数组都编在
        # .rodata 里，能现场反解。返回它自己，让下游按 Image 处理。
        return blob, "image"

    seen = []
    for magic, kind in MAGICS:
        start = 0
        tried = 0
        while tried < 16:
            idx = blob.find(magic, start)
            if idx < 0:
                break
            tried += 1
            try:
                data = _dec(kind, blob[idx:])
            except AdapterError:
                raise
            except Exception:
                data = b""
            # 必须是 ELF：kernel 段里撞上 gzip 魔数的假流解出来是
            # 许可文本、字符串表之类（实测遇到过一次，解出 "#\n# "）
            if data[:4] == b"\x7fELF":
                return data, f"{kind}@{idx}"
            if data and _looks_like_arm64_image(data):
                # Image.gz 解开成 Image —— 一样能用，符号表在它自己里面
                return data, f"{kind}@{idx}"
            if data:
                seen.append(f"{kind}@{idx}→{data[:8]!r}")
            start = idx + 1

    hint = ""
    if seen:
        hint = "。解出过但都不是 ELF：" + "，".join(seen[:4])
    raise AdapterError(
        "kernel 段里找不到能解成 ELF 的压缩流（gzip/xz/lzma/lz4/zstd 都试过）" + hint +
        "。这个 kernel 可能被二次封装，或直接给固件包里的 vmlinux.elf 更快")


def vmlinux_from_boot(boot_path, out_path, log=None):
    """boot.img → vmlinux.elf，返回 (out_path, 算法)"""
    def say(s):
        if log:
            log(s)
    raw = slice_kernel(boot_path)
    say(f"  kernel 段 {len(raw)} 字节")
    data, kind = decompress_kernel(raw)
    if data[:4] != b"\x7fELF" and not _looks_like_arm64_image(data):
        raise AdapterError(f"解压出来既不是 ELF 也不是 ARM64 Image"
                           f"（前 4 字节 {data[:4]!r}，算法 {kind}）。"
                           f"这个 kernel 可能被二次封装了")
    with open(out_path, "wb") as f:
        f.write(data)
    what = "ELF" if data[:4] == b"\x7fELF" else "裸 ARM64 Image（kallsyms 可反解）"
    say(f"  解压算法 {kind}，得到 {len(data)} 字节 {what}")
    return out_path, kind


def adb_path():
    """内嵌 adb 优先，退回 PATH 里的 adb。"""
    p = _res("assets", "adb", "adb.exe")
    if os.path.isfile(p):
        return p
    return shutil.which("adb") or "adb"


def grab_kallsyms(out_path=None, serial=None, adb=None, log=None):
    """
    从连着 USB 的设备上现场导出 /proc/kallsyms，返回 (out_path, 统计dict)。

    为什么用 exec-out 而不是 shell：`adb shell` 会做 CRLF 转换和编码转换，
    12 万行里混进 \\r 之后有些解析器会吃掉行尾字符；exec-out 是二进制透传。

    为什么先 su 再 cat：kptr_restrict=1 时非 root 读到的地址全是 0，
    这份文本看着有 12 万行其实一个字都用不了 —— 所以必须 su，
    而且拉完要统计零地址数量并直接报错，不能让用户拿着废文件去生成 target.h。
    """
    def say(s):
        if log:
            log(s)

    adb = adb or adb_path()
    out_path = out_path or os.path.join(
        os.getcwd(), "kallsyms-%s.txt" % time.strftime("%Y%m%d-%H%M%S"))

    base = [adb]
    if serial:
        base += ["-s", serial]

    # 先确认有设备
    r = subprocess.run(base + ["devices"], capture_output=True, timeout=30,
                       creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    txt = (r.stdout or b"").decode("utf-8", "replace")
    devs = [l.split("\t")[0] for l in txt.splitlines()[1:]
            if "\tdevice" in l]
    if not devs:
        raise AdapterError("没有处于 device 状态的设备。\n"
                           "  adb devices 输出：\n" + txt.strip())
    if not serial and len(devs) > 1:
        raise AdapterError("连了多台设备（%s），用 --serial 指定一台"
                           % ", ".join(devs))
    cur = serial or devs[0]
    say(f"  设备 {cur}")

    # 1) 关掉地址隐藏（失败不算致命，后面用零地址比例判定）
    subprocess.run(base + ["shell", "su", "-c",
                           "echo 0 > /proc/sys/kernel/kptr_restrict"],
                   capture_output=True, timeout=30,
                   creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))

    # 2) exec-out 二进制透传
    say("  导出 /proc/kallsyms（12 万行左右，约 6MB，等十几秒）")
    with open(out_path, "wb") as f:
        p = subprocess.Popen(base + ["exec-out", "su", "-c",
                                     "cat /proc/kallsyms"],
                             stdout=f, stderr=subprocess.PIPE,
                             creationflags=getattr(
                                 subprocess, "CREATE_NO_WINDOW", 0))
        try:
            err = p.communicate(timeout=180)[1]
        except subprocess.TimeoutExpired:
            # 挂住的 adb 必须杀掉，否则它占着 server，后面每个 adb 命令都会卡
            p.kill()
            p.communicate()
            try:
                os.remove(out_path)        # 半截文件不能留着误事
            except OSError:
                pass
            raise AdapterError("导出超过 180 秒没结束，已中止。\n"
                               "  设备可能锁屏了（锁屏后 exec-out 会挂住），"
                               "解锁后重试")
    if p.returncode != 0:
        try:
            os.remove(out_path)
        except OSError:
            pass
        e = (err or b"").decode("utf-8", "replace").strip()
        raise AdapterError(
            "导出失败（exit %s）：%s\n"
            "  多半是 su 没授权。先在设备上确认：\n"
            "    adb shell su -c 'id'    → 应输出 uid=0(root)"
            % (p.returncode, e or "无 stderr"))

    # 3) 校验：正常应是 6MB / 12 万行；全零地址必须报错
    size = os.path.getsize(out_path)
    ks = elfsyms.Kallsyms(out_path)
    say(f"  {size} 字节，{ks.total} 行，有效符号 {len(ks.symbols())}，"
        f"零地址 {ks.zeroed}")
    if size < 512 * 1024:
        raise AdapterError(
            "导出只有 %d 字节，太小了。设备上 /proc/kallsyms 一般 5~7MB。\n"
            "  su 可能没拿到 root，或内核编译时关了 CONFIG_KALLSYMS。"
            % size)
    if ks.zeroed:
        raise AdapterError(
            "有 %d/%d 条地址是 0，这份文件不能用（kptr_restrict 没关掉）。\n"
            "  设备上手动确认：\n"
            "    adb shell su -c 'cat /proc/sys/kernel/kptr_restrict'   → 想要 0\n"
            "    adb shell su -c 'head -3 /proc/kallsyms'              → 第一列不能全 0\n"
            "  有些内核不允许改这个值，那就只能走 vmlinux.elf 那条路。"
            % (ks.zeroed, ks.total))
    if "_text" not in ks.symbols():
        raise AdapterError("这份 kallsyms 里没有 _text，可能被裁剪过")
    base_addr = ks.symbols()["_text"][0]
    say(f"  _text = 0x{base_addr:016X}")
    return out_path, {"lines": ks.total, "syms": len(ks.symbols()),
                      "size": size, "text": base_addr, "serial": cur}


# ----------------------------------------------------------------------
# target.h 生成
# ----------------------------------------------------------------------
def _sub_macro(txt, name, literal, comment_keep=True):
    """把 `#define NAME <数字><后缀><行尾注释>` 里的数字换掉，保留后缀与注释"""
    pat = re.compile(
        r"^(#define\s+" + re.escape(name) + r"\s+)"
        r"(0[xX][0-9a-fA-F]+|\d+)"
        r"(ULL|UL|U|L|LL|ull|ul|u|l|ll)?"
        r"(.*)$", re.M)
    m = pat.search(txt)
    if not m:
        return txt, False
    suffix = m.group(3) or ""
    tail = m.group(4) if comment_keep else ""
    new = f"{m.group(1)}{literal}{suffix}{tail}"
    return txt[:m.start()] + new + txt[m.end():], True


def suggest_id(fingerprint, kernel_ver):
    """给新 target 起个短 id：migr-<指纹前 8 位>"""
    h = hashlib.sha1((fingerprint or "unknown").encode("utf-8")).hexdigest()[:8]
    k = re.sub(r"[^0-9A-Za-z._-]+", "_", (kernel_ver or "kernel"))[:24]
    return f"migr-{k}-{h}"


def build_target_h(template_path, out_path, offsets, fingerprint, kernel_ver,
                   log=None, syms_mode="trust", manual_values=None):
    """
    读模板，替换符号偏移，把手工宏标成占位符。

    syms_mode:
      "trust" —— 全部采用 vmlinux 提取值（适配新内核必须用这个）
      "keep"  —— 只替换"模板值与提取值相同"的宏，其余保留模板原值
                 （同版本重编、不想动已验证配置时用）

    manual_values: {宏名: 值} —— 自动化流程从镜像反汇编推出来的手工宏。
      给了就写进文件，不再留占位符；没给的照旧留 FILL_MARK，逼人来看。

    返回 (unfilled, notfound, diffs)
      diffs: [(macro, 模板值, 提取值)] —— 两边不一致的清单
    """
    def say(s):
        if log:
            log(s)

    with open(template_path, encoding="utf-8") as f:
        txt = f.read()

    orig_len = len(txt)
    replaced, notfound, diffs = [], [], []

    # 先记下模板原值，用来判"同源"还是"换版本"
    pat = re.compile(r"^#define\s+(\w+)\s+(0[xX][0-9a-fA-F]+|\d+)", re.M)
    orig = {}
    for m in pat.finditer(txt):
        orig.setdefault(m.group(1), int(m.group(2), 0))

    for macro, val in offsets.items():
        o = orig.get(macro)
        if o is not None and o != val:
            diffs.append((macro, o, val))
            if syms_mode == "keep":
                continue          # 保留模板值，只报告
        lit = f"0x{val:012X}"
        txt, ok = _sub_macro(txt, macro, lit)
        if ok:
            replaced.append(macro)
        else:
            notfound.append(macro)

    # 手工宏：能从镜像推出来的直接写值，推不出来的留醒目占位逼人确认
    unfilled = []
    manual_values = manual_values or {}
    for macro, _hint in MANUAL_MACROS:
        v = manual_values.get(macro)
        if v is not None:
            txt, ok = _sub_macro(txt, macro, f"0x{v:X}")
            if ok:
                say(f"  {macro:<28} = 0x{v:X}  （自动推导）")
                continue
        txt, ok = _sub_macro(txt, macro, f"{FILL_MARK} 0x0")
        if ok:
            unfilled.append(macro)
        else:
            say(f"  [警告] 模板里没有 {macro}，这个版本的 target.h 结构变了")

    # 标识与指纹
    txt = re.sub(r'#define\s+BUILD_VARIANT_LABEL\s+"[^"]*"',
                 f'#define BUILD_VARIANT_LABEL "migrated_{re.sub(r"[^0-9A-Za-z._-]", "_", os.path.basename(os.path.dirname(out_path)))}"',
                 txt)
    if fingerprint:
        txt = re.sub(r'#define\s+BUILD_FINGERPRINT\s+"[^"]*"',
                     f'#define BUILD_FINGERPRINT "{fingerprint}"', txt)

    # 顶部加一段"这是迁移生成的"横幅，防止跟原版混淆
    banner = (
        f"/* ===== 由 Leaf5RootTool 适配向导生成 {time.strftime('%Y-%m-%d %H:%M:%S')} =====\n"
        f" * kernel   : {kernel_ver or '?'}\n"
        f" * version  : {fingerprint or '?'}\n"
        f" * 符号偏移 : 自动从 vmlinux 提取（{len(replaced)} 个）\n"
        f" * 模板差异 : {len(diffs)} 个宏与模板原值不同"
        f"{'（syms_mode=keep，已保留模板值）' if syms_mode == 'keep' else ''}\n"
        f" * 待人工填 : {', '.join(unfilled) if unfilled else '无'}\n"
        f" * 填完才能编译：占位符留在源码里会编不过\n"
        f" * ======================================================== */\n"
    )
    txt = banner + txt

    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w", encoding="utf-8", newline="\n") as f:
        f.write(txt)

    say(f"  写出 {out_path}（{len(txt)} 字节，模板 {orig_len}）")
    if notfound:
        say(f"  [警告] 模板里找不到这些宏：{', '.join(notfound)}")
    if diffs:
        say(f"  [i] {len(diffs)} 个宏与模板原值不同：")
        for macro, o, v in diffs:
            say(f"      {macro:<32} 模板 0x{o:X}  符号表 0x{v:X}  "
                f"({v - o:+d})")
    return unfilled, notfound, diffs


# ----------------------------------------------------------------------
# 编译
# ----------------------------------------------------------------------
def _run(args, cwd, timeout=600):
    flags = 0x08000000 if os.name == "nt" else 0     # CREATE_NO_WINDOW
    return subprocess.run(args, cwd=cwd, capture_output=True,
                          timeout=timeout, creationflags=flags)


def _as_cmd(cc, argv):
    """
    Windows 下 NDK 给的是 aarch64-linux-android35-clang.cmd（一层批处理包装）。
    走 cmd /c 传参时，-DTARGET_CONFIG_H=\\"...\\" 这种带引号的宏会被 cmd
    二次转义，实测直接编译会失败（报宏未定义）。

    解法：用同目录的 clang.exe 直接调，target triple 由 argv 里的
    --target= 指定，效果等价，绕开 cmd 层。
    """
    if cc.lower().endswith(".cmd"):
        exe = os.path.join(os.path.dirname(cc), "clang.exe")
        if os.path.isfile(exe):
            return [exe] + argv
        return ["cmd", "/c", cc] + argv
    return [cc] + argv


def _rel(p, base):
    """跨盘符时 relpath 会抛 ValueError，退回绝对路径（统一正斜杠）"""
    try:
        return os.path.relpath(p, base).replace("\\", "/")
    except ValueError:
        return os.path.abspath(p).replace("\\", "/")


def _sysroot_of(cc):
    # .../prebuilt/<host>/bin/<cc>  →  .../prebuilt/<host>/sysroot
    prebuilt = os.path.dirname(os.path.dirname(os.path.abspath(cc)))
    return os.path.join(prebuilt, "sysroot")


def ensure_wallpaper(exploit_dir):
    """src/assets/wallpaper.webp 是 .incbin 的相对目标，缺了就补 40 字节占位"""
    dst = os.path.join(exploit_dir, "src", "assets", "wallpaper.webp")
    if os.path.isfile(dst):
        return dst
    src = os.path.join(exploit_dir, "assets", "wallpaper.webp")
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    if os.path.isfile(src):
        shutil.copyfile(src, dst)
        return dst
    # 兜底：跟 Makefile 里那段 python 生成逻辑等价
    d = b"RIFF" + struct.pack("<I", 0) + b"WEBP" + b"VP8 " + struct.pack("<I", 30)
    d += bytes([0x9d, 0x01, 0x2a, 0x01, 0x00, 0x01, 0x00])
    d += bytes([0x01, 0x40, 0x25, 0xa4, 0x00, 0x03, 0x70, 0x00])
    d += bytes([0xfe, 0xfb, 0x94, 0x00, 0x00])
    d = d[:4] + struct.pack("<I", len(d) - 8) + d[8:]
    with open(dst, "wb") as f:
        f.write(d)
    return dst


C_SRCS = ["main.c", "util.c", "slide.c", "fops.c", "pipe.c", "root.c",
          "preload.c", "heap_spray.c", "kgsl_route.c"]
ASM_SRCS = ["su_blob.S", "wallpaper_blob.S"]


def compile_preload(exploit_dir, target_dir, cc, out_so, log=None,
                    cancel=None):
    """
    三段编译（顺序不能换）：
      ① su_daemon → out/exploit/aarch64/embed/su_daemon_aarch64_pie
      ② su_blob.S 里的 .incbin 直接吃 ①的产物
      ③ 主链接
    返回 out_so 路径。
    """
    def say(s):
        if log:
            log(s)
    def chk():
        if cancel and cancel():
            raise AdapterError("已取消")

    exploit_dir = os.path.abspath(exploit_dir)
    target_dir = os.path.abspath(target_dir)
    sysroot = _sysroot_of(cc)
    if not os.path.isdir(sysroot):
        raise AdapterError(f"sysroot 不存在：{sysroot}（NDK 安装不完整？）")
    if not os.path.isfile(os.path.join(target_dir, "target.h")):
        raise AdapterError(f"{target_dir} 下没有 target.h")

    # target.h 里的占位符还没填就别浪费 3 分钟
    with open(os.path.join(target_dir, "target.h"), encoding="utf-8") as f:
        th = f.read()
    left = re.findall(r"#define\s+(\w+)\s+" + re.escape(FILL_MARK), th)
    if left:
        raise AdapterError("target.h 里这些宏还是占位符没填：" +
                           ", ".join(left) +
                           "。按 MIGRATION 说明填完再编译，否则编出来是错的")

    ensure_wallpaper(exploit_dir)

    embed_dir = os.path.join(exploit_dir, "out", "exploit", "aarch64", "embed")
    os.makedirs(embed_dir, exist_ok=True)
    daemon = os.path.join(embed_dir, "su_daemon_aarch64_pie")

    # ① su_daemon（PIE 独立可执行，会被 incbin 进 .rodata）
    #    必须 -static：动态版只有 15KB，设备上没有对应 linker/interp 路径，
    #    push 上去直接跑不起来。静态版 2251616 字节，EXE 里出厂载荷就是它。
    say("  ① 编译 su_daemon（静态，约 30 秒）…")
    chk()
    r = _run(_as_cmd(cc, [
        f"--target=aarch64-linux-android{TARGET_API}",
        f"--sysroot={sysroot}", "-O2", "-static", "-pie",
        "src/su_daemon.c", "-o", _rel(daemon, exploit_dir),
    ]), cwd=exploit_dir, timeout=300)
    if r.returncode != 0 or not os.path.isfile(daemon):
        raise AdapterError("su_daemon 编译失败：\n" +
                           (r.stderr or b"").decode("utf-8", "replace")[-1500:])
    say(f"     {os.path.getsize(daemon)} 字节")

    # .incbin "../out/exploit/aarch64/embed/su_daemon_aarch64_pie" 的解析基准
    # 在 clang 上不唯一：实测 cwd 优先、源文件所在目录兜底。两种位置都放一份，
    # 否则会读到上一次编译留下的旧文件（尺寸对不上，编出来的 so 是错的）。
    alt_embed = os.path.join(os.path.dirname(exploit_dir),
                             "out", "exploit", "aarch64", "embed")
    if os.path.abspath(alt_embed) != os.path.abspath(embed_dir):
        os.makedirs(alt_embed, exist_ok=True)
        try:
            shutil.copyfile(daemon, os.path.join(alt_embed,
                                                 "su_daemon_aarch64_pie"))
        except OSError as e:
            say(f"    [!] 备用 embed 目录写入失败（不影响本次编译）：{e}")

    # ②③ 主链接
    say("  ② 链接 preload.so（9 个 .c + 2 个 .S，约 1 分钟）…")
    chk()
    os.makedirs(os.path.dirname(os.path.abspath(out_so)), exist_ok=True)
    rel_tgt = _rel(target_dir, exploit_dir)
    argv = [
        f"--target=aarch64-linux-android{TARGET_API}",
        f"--sysroot={sysroot}",
        "-I.", "-Isrc", f"-I{rel_tgt}",
        "-O2", "-fPIC", "-shared",
        # 这里必须是纯双引号，不能写成 \" —— clang 会把反斜杠当字面量，
        # 宏展开成 \"targets/... 缺终止引号，#include 直接失效（实测报
        # "missing terminating '\"' character"，然后整批宏未定义）
        f'-DTARGET_CONFIG_H="{rel_tgt}/target.h"',
        "-DFUTEX_KEY_LAYOUT_V1",
        "-pthread",
    ] + [f"src/{s}" for s in C_SRCS + ASM_SRCS] + [
        "-o", _rel(out_so, exploit_dir),
    ]
    r = _run(_as_cmd(cc, argv), cwd=exploit_dir, timeout=900)
    if r.returncode != 0 or not os.path.isfile(out_so):
        raise AdapterError("preload.so 链接失败：\n" +
                           (r.stderr or b"").decode("utf-8", "replace")[-2000:])

    size = os.path.getsize(out_so)
    md5 = hashlib.md5(open(out_so, "rb").read()).hexdigest()
    say(f"     {size} 字节  md5={md5}")
    return out_so, md5, size


# ----------------------------------------------------------------------
# 源码工作区
# ----------------------------------------------------------------------
def _res(*parts):
    """打包后取 sys._MEIPASS，开发时取脚本目录"""
    base = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base, *parts)


def work_repo():
    """适配工作区根。目录结构跟仓库一致：<root>/exploit/{src,targets,out}"""
    return os.path.join(
        os.environ.get("LOCALAPPDATA", os.path.expanduser("~")),
        "Leaf5RootTool", "src")


def _packaged_exploit():
    """EXE 里带着的 exploit 源码根；开发模式下退回同级的 leaf5-ghostlock"""
    p = _res("assets", "exploit_src", "exploit")
    if os.path.isdir(p):
        return p
    here = os.path.dirname(os.path.abspath(__file__))
    alt = os.path.join(os.path.dirname(here), "leaf5-ghostlock", "exploit")
    return alt if os.path.isdir(alt) else None


def ensure_src(log=None, force=False):
    """
    把 exploit 源码铺到工作区，返回 <repo>/exploit 的路径。

    覆盖策略：
      src/ 与 targets/onyx-leaf5/  —— 每次覆盖（模板，用户不该改）
      targets/migr-*/              —— 绝不覆盖（用户适配出来的成果）
    """
    def say(s):
        if log:
            log(s)

    src = _packaged_exploit()
    if not src:
        raise AdapterError("找不到 exploit 源码（EXE 里没打包 assets/exploit_src）")

    dst_root = work_repo()
    dst = os.path.join(dst_root, "exploit")
    os.makedirs(dst, exist_ok=True)

    n = 0
    for sub in ("src", "assets"):
        s = os.path.join(src, sub)
        if not os.path.isdir(s):
            continue
        d = os.path.join(dst, sub)
        os.makedirs(d, exist_ok=True)
        # 必须递归：src/kernelsnitch/ 里的头文件是编译依赖
        for root, _dirs, files in os.walk(s):
            rel = os.path.relpath(root, s)
            tdir_ = d if rel == "." else os.path.join(d, rel)
            os.makedirs(tdir_, exist_ok=True)
            for name in files:
                if ".bak" in name:
                    continue
                sp = os.path.join(root, name)
                dp = os.path.join(tdir_, name)
                need = (force or not os.path.isfile(dp)
                        or os.path.getsize(sp) != os.path.getsize(dp))
                if need:
                    shutil.copyfile(sp, dp)
                    n += 1

    # 模板 target.h 单独处理，放 targets/onyx-leaf5/
    t = os.path.join(src, "targets", "onyx-leaf5", "target.h")
    if os.path.isfile(t):
        td = os.path.join(dst, "targets", "onyx-leaf5")
        os.makedirs(td, exist_ok=True)
        dp = os.path.join(td, "target.h")
        if force or not os.path.isfile(dp) or os.path.getsize(t) != os.path.getsize(dp):
            shutil.copyfile(t, dp)
            n += 1

    # src/assets/wallpaper.webp 是 .incbin 的相对目标，必须在 src/ 下
    ensure_wallpaper(dst)

    os.makedirs(os.path.join(dst, "out", "exploit", "aarch64", "embed"),
                exist_ok=True)
    if n:
        say(f"  源码工作区同步了 {n} 个文件 → {dst}")
    else:
        say(f"  源码工作区已是最新 → {dst}")
    return dst


# ----------------------------------------------------------------------
# 本机内核镜像自动发现
# ----------------------------------------------------------------------
# 能自动的是「找出本机已有的镜像」，不能自动的是「凭空造出带符号的 vmlinux」。
# 带符号的 vmlinux 只有两个来路：厂商固件包里附的 debug 内核，或自己 dump
# 后配 System.map。前者扫得到，后者要做 kallsyms 反解（本工具没实现）。
# 所以这里只负责把「本机本来就有的」捞出来，不去猜、不去网上抓。
SCAN_SKIP_DIRS = {
    "node_modules", ".git", ".svn", "$RECYCLE.BIN", "System Volume Information",
    "Windows", "WinSxS", "Installer", "System32", "__pycache__", ".gradle",
    ".android", ".cache", "site-packages",
    # 系统与缓存区：不可能放内核镜像，但文件数占全盘大半。
    # 自己的 %LOCALAPPDATA%\Leaf5RootTool 是作为独立 root 传进来的，
    # 不受这里影响（BFS 从它自己开始）。
    "AppData", "Application Data", "Local Settings", "ProgramData",
    "Program Files", "Program Files (x86)", "Recovery", "PerfLogs", "MSOCache",
}
# 注意：故意不收 ".txt" —— 全盘扫时 txt 文件几十万个，每个都要读头部判格式，
# 代价远大于收益。kallsyms 导出文件靠 _SCAN_HINTS 里的文件名（kallsyms/system.map）
# 和 .map 扩展名命中；用户手动拖进来的文件不走这套过滤，什么扩展名都能收。
SCAN_EXT = (".elf", ".img", ".bin", ".Image", ".map")
_SCAN_HINTS = ("vmlinux", "kernel", "boot", "image", "kallsyms", "system.map",
               "system_map")
SCAN_MIN_BYTES = 256 * 1024       # kallsyms 文本小的也有 500KB，二进制内核更大


def _scan_roots():
    """扫这些地方：EXE 旁边、当前目录、工具自己的目录、下载/桌面/文档"""
    roots = []

    def add(p):
        if not p:
            return
        try:
            if os.path.isdir(p):
                rp = os.path.abspath(p)
                if rp not in roots:
                    roots.append(rp)
        except OSError:
            pass

    # PyInstaller 下 sys.executable 是 dist/ 里的 exe，os.getcwd() 才是启动处
    add(os.path.dirname(os.path.abspath(sys.argv[0] if getattr(sys, "frozen", False)
                                       else __file__)))
    add(os.getcwd())
    add(os.path.join(os.environ.get("LOCALAPPDATA", ""), "Leaf5RootTool"))
    home = os.environ.get("USERPROFILE") or os.path.expanduser("~")
    for sub in ("Downloads", "Desktop", "Documents",
                os.path.join("OneDrive", "Desktop"),
                os.path.join("OneDrive", "Downloads"),
                os.path.join("OneDrive - SUM WAH TRANSPORT ENTERPRISES CO LTD", "桌面")):
        add(os.path.join(home, sub))
    return roots


BANNER_RE = re.compile(rb"Linux version ([\x20-\x7e]{16,240})")
_COMMIT_RE = re.compile(r"perf-g([0-9a-f]{8,16})")
_BUILD_RE = re.compile(r"#(\d+)")


def read_kernel_banner(path):
    """
    在 kernel Image 里找 linux_banner 字符串。

    这是唯一一个「零权限、从镜像本身就能读到」的构建身份：内核启动时
    /proc/version 打印的就是它，同一个字符串还躺在镜像里。不依赖符号表、
    不依赖文件格式，直接字节搜。用它跟设备对一下，就不用猜手里这个镜像
    是不是设备上正在跑的那个。
    """
    try:
        is_boot = False
        with open(path, "rb") as f:
            is_boot = f.read(8) == b"ANDROID!"
    except OSError:
        return None
    try:
        data = slice_kernel(path) if is_boot else open(path, "rb").read()
    except (AdapterError, OSError):
        return None
    m = BANNER_RE.search(data)
    if not m:
        return None
    return m.group(1).decode("latin1").strip()


def parse_banner(text):
    """把 banner 拆成可比对的字段。缺的给 None，不抛。"""
    if not text:
        return {}
    out = {"raw": text}
    m = _COMMIT_RE.search(text)
    out["commit"] = m.group(1) if m else None
    m = _BUILD_RE.search(text)
    out["build"] = int(m.group(1)) if m else None
    if "(" in text and ")" in text:
        out["compiler"] = text[text.find("(") + 1:text.rfind(")")]
    # read_kernel_banner 抓到的是 "4.19.157-perf-g..." 开头（没有 "Linux version " 前缀），
    # 而设备 /proc/version 抓的是带前缀的整行。两种都得认，别按空格切死。
    m = re.search(r"(\d+\.\d+\.\d+[^\s]*)", text)
    out["version"] = m.group(1) if m else ""
    out["dirty"] = "-dirty" in text
    return out


def banner_match(banner, dev_version):
    """
    镜像 banner vs 设备 /proc/version。

    返回 (verdict, why, advice)。verdict：
      same      同一构建 —— 偏移直接用
      resame    同 commit、build 号不同 —— 同源码重编，多半能对上，但 CONFIG 变了就不同
      dirty     commit 与 build 都同、但带 -dirty —— commit 不代表内容，只能当参考
      different 不同内核 —— 偏移必错
      unknown   有一边解析不出来
    """
    a = parse_banner(banner)
    b = parse_banner(dev_version)
    if not a.get("commit") or not b.get("commit"):
        return ("unknown",
                "有一边读不到 git commit（镜像里没有 linux_banner，或设备没连）",
                "设备已 root 的话，dd 出对应 boot 分区比对 sha256 更硬")
    if a["commit"] != b["commit"]:
        return ("different",
                "镜像 commit %s，设备 commit %s" % (a["commit"], b["commit"]),
                "这不是同一个内核。用它算出的偏移会让漏洞链打偏、在内核里"
                "随机位置崩 —— 换设备上正在跑的那个 boot 分区镜像")
    if a.get("build") != b.get("build"):
        return ("resame",
                "同 commit %s，build 号 %s vs %s"
                % (a["commit"], a.get("build"), b.get("build")),
                "同源码不同次编译，.config 一致时偏移应当相同；先在设备上验一遍")
    if a.get("dirty") or b.get("dirty"):
        return ("dirty",
                "commit 与 build 号都对得上（%s #%s），但带 -dirty"
                % (a["commit"], a.get("build")),
                "-dirty 说明编译时工作区有未提交改动，commit 代表不了二进制内容；"
                "镜像段的 sha256 才是硬证据")
    return ("same",
            "同一构建 %s #%s %s" % (a.get("version"), a.get("build"), a["commit"]),
            "偏移可用")


def _adb_read(remote, adb=None, serial=None, env=None):
    """读设备上一个文本文件，返回 (ok, bytes)。不做 su，失败不抛。"""
    adb = adb or adb_path()
    base = [adb] + (["-s", serial] if serial else [])
    try:
        r = subprocess.run(base + ["exec-out", "cat", remote],
                           capture_output=True, timeout=30, env=env,
                           creationflags=getattr(
                               subprocess, "CREATE_NO_WINDOW", 0))
    except (subprocess.TimeoutExpired, OSError):
        return False, b""
    return r.returncode == 0 and bool(r.stdout), (r.stdout or b"")


def banner_check(path, adb=None, serial=None, env=None, log=None):
    """
    读镜像 banner → 连设备读 /proc/version → 给结论。设备不在也不抛。
    """
    def say(x):
        if log:
            log(x)

    mine = read_kernel_banner(path)
    if not mine:
        return None
    say("  镜像 banner: %s" % mine)
    dev = None
    ok, out = _adb_read("/proc/version", adb=adb, serial=serial, env=env)
    if ok:
        dev = out.decode("latin1").strip()
    if not dev:
        return dict(image=mine, device=None, verdict="unknown",
                    why="设备没连（或 /proc/version 读不出来），只解析了镜像",
                    advice="连上设备再跑一次")
    say("  设备 version: %s" % dev)
    v, why, adv = banner_match(mine, dev)
    tag = {"same": "[OK]", "resame": "[!]", "dirty": "[!]",
           "different": "[X]", "unknown": "[?]"}[v]
    say("  %s %s" % (tag, why))
    if v != "same":
        say("      %s" % adv)
    return dict(image=mine, device=dev, verdict=v, why=why, advice=adv)


def resolve_syms_source(path, log=None, keep=None):
    """
    把任意来源统一成「open_syms 能直接吃的文件路径」。

    boot.img 会切出 kernel 段、解压到临时文件再用 —— 调用方不需要知道
    进来的是 boot 还是裸 Image 还是 ELF，拿到的永远是一个能读符号表的文件。

    返回 (path, how, banner)。how 是说明用的字符串（"direct" / "image@0x..."），
    banner 是镜像里 linux_banner 的原文（读不到给 None）。
    """
    def say(x):
        if log:
            log(x)
    try:
        with open(path, "rb") as f:
            head = f.read(8)
    except OSError as ex:
        raise AdapterError(f"打不开 {path}：{ex}")
    if head != b"ANDROID!":
        return path, "direct", read_kernel_banner(path)

    say(f"  {os.path.basename(path)} 是 boot.img，先切 kernel 段")
    raw = slice_kernel(path)
    data, how = decompress_kernel(raw)
    if keep:
        out = keep
    else:
        suf = ".elf" if data[:4] == b"\x7fELF" else ".img"
        fd, out = tempfile.mkstemp(prefix="leaf5-kernel-", suffix=suf)
        os.close(fd)
    with open(out, "wb") as f:
        f.write(data)
    say(f"  kernel 段 {len(raw)} 字节，{how}，落盘 {len(data)} 字节 → {out}")
    return out, how, read_kernel_banner(out)


def probe_kernel(path, deep=True):
    """
    判定单个文件能不能当内核用。

    返回 dict(path, size, kind, usable, note) 或 None（不是内核镜像）。
    usable 的判据是「能取到符号且有 _text」—— 少了这个，后面生成 target.h
    那步必然失败，所以提前判掉，别让用户选了才发现白忙。

    kind 三种：elf（vmlinux）、syms（kallsyms / System.map 文本）、boot（boot.img）
    """
    try:
        size = os.path.getsize(path)
        if size < 64 * 1024:
            return None
        with open(path, "rb") as f:
            head = f.read(8)
    except OSError:
        return None

    if head[:4] == b"\x7fELF":
        if not deep:
            return dict(path=path, size=size, kind="elf", usable=True, note="")
        try:
            with elfsyms.Elf64(path) as e:
                syms = e.symbols()
        except Exception as ex:
            return dict(path=path, size=size, kind="elf", usable=False,
                        note=f"ELF 取不到符号表：{ex}")
        if "_text" not in syms:
            return dict(path=path, size=size, kind="elf", usable=False,
                        note="ELF 但没有 _text 符号（strip 过），偏移无从算起")
        return dict(path=path, size=size, kind="elf", usable=True,
                    note=f"{len(syms)} 个符号")

    if head[:8] == b"ANDROID!":
        if not deep:
            return dict(path=path, size=size, kind="boot", usable=True,
                        note="boot.img（kernel 段可反解 kallsyms）")
        # deep 时真解一遍：切 kernel 段 → 解压 → 看是不是 ELF/Image。
        # 这一步要读几十 MB，只在用户明确选中时才做。
        try:
            raw = slice_kernel(path)
            data, how = decompress_kernel(raw)
        except Exception as ex:
            return dict(path=path, size=size, kind="boot", usable=False,
                        note=f"boot.img 解不出内核：{ex}")
        if data[:4] == b"\x7fELF":
            return dict(path=path, size=size, kind="boot", usable=True,
                        note=f"kernel 段 {how} → ELF")
        return dict(path=path, size=size, kind="boot", usable=True,
                    note=f"kernel 段 {how} → 裸 ARM64 Image（可反解 kallsyms）")

    # 裸 ARM64 Image：偏移 0x38 是 "ARM\x64"
    # 这条路上限最高：设备没 root、外部又拿不到 vmlinux 时，boot 分区的 kernel
    # 段就是唯一原料。kallsyms 的 token 表 + 偏移数组本来就编在 .rodata 里，
    # 现场反解即可，不需要任何外部文件。
    try:
        with open(path, "rb") as f:
            f.seek(0x38)
            is_image = f.read(4) == b"ARM\x64"
    except OSError:
        is_image = False
    if is_image:
        if not deep:
            return dict(path=path, size=size, kind="image", usable=True,
                        note="裸 ARM64 Image（可反解 kallsyms）")
        try:
            import imageksym
            with imageksym.ImageKallsyms(path) as ks:
                lay = ks.locate()
                syms = ks.symbols()
        except Exception as ex:
            return dict(path=path, size=size, kind="image", usable=False,
                        note=f"裸 ARM64 Image，kallsyms 反解失败：{ex}")
        if "_text" not in syms:
            return dict(path=path, size=size, kind="image", usable=False,
                        note="反解出了符号表但没有 _text，偏移无从算起")
        return dict(path=path, size=size, kind="image", usable=True,
                    note=f"{len(syms)} 个符号（从镜像反解，{lay['count']} 条）")

    # kallsyms / System.map 文本：地址 类型 名字
    if size >= 256 * 1024 and elfsyms.looks_like_kallsyms(path):
        if not deep:
            return dict(path=path, size=size, kind="syms", usable=True,
                        note="kallsyms 文本")
        ks = elfsyms.Kallsyms(path)
        syms = ks.symbols()
        if ks.zeroed:
            return dict(path=path, size=size, kind="syms", usable=False,
                        note=f"kallsyms 文本，但 {ks.zeroed} 条地址为 0"
                             f"（kptr_restrict 没关）")
        if "_text" not in syms:
            return dict(path=path, size=size, kind="syms", usable=False,
                        note="kallsyms 文本，但没有 _text，片段不完整")
        return dict(path=path, size=size, kind="syms", usable=True,
                    note=f"{len(syms)} 个符号（kallsyms 文本）")

    return None


def scan_kernels(roots=None, max_depth=3, budget=8.0, limit=20000, log=None,
                 stop=None, first_hit=False):
    """
    在常见目录里找现成的内核镜像。返回 (usable, others)。

      usable —— 带符号 ELF，能直接拿去生成 target.h
      others —— 找到了但用不上（boot.img / strip 过），列出来免得用户以为没扫到

    复杂度 O(访问的文件数)，用深度、条目数、墙钟三重预算卡住：用户目录可能
    有几十万文件，扫穿了会让向导启动卡十几秒。
    stop 是可选中途取消回调，返回 True 就收工；first_hit=True 时找到第一个
    可用镜像就收工（深扫用，用户要的是"能用"，不是"全都列出来"）。
    """
    import collections
    import time

    def say(s):
        if log:
            log(s)

    roots = roots or _scan_roots()
    usable, others = [], []
    seen = set()
    seen_dir = set()
    t0 = time.time()
    visited = 0

    def norm(p):
        return os.path.normcase(os.path.abspath(p))

    q = collections.deque((r, 0) for r in roots)
    while q:
        if time.time() - t0 > budget or visited > limit:
            say(f"  扫描预算用尽（{visited} 个条目，{time.time() - t0:.1f}s），"
                f"只列已找到的")
            break
        if stop and stop():
            say(f"  已取消（扫了 {visited} 个条目）")
            break
        d, depth = q.popleft()
        try:
            it = os.scandir(d)
        except OSError:
            continue
        with it:
            for ent in it:
                visited += 1
                if visited > limit:
                    break
                try:
                    if ent.is_dir(follow_symlinks=False):
                        name = ent.name
                        if depth >= max_depth:
                            continue
                        if name in SCAN_SKIP_DIRS or name.startswith("."):
                            continue
                        # 用规范化路径去重，不用 inode —— Windows 下
                        # DirEntry.stat() 的 st_ino 恒为 0（走 FindFirstFile，
                        # 拿不到 file index），拿它去重会把 116 个目录判成同一个，
                        # 整棵树只展开第一层。这个坑是实测出来的，别改回去。
                        key = norm(ent.path)
                        if key in seen_dir:
                            continue
                        seen_dir.add(key)
                        q.append((ent.path, depth + 1))
                        continue
                    if not ent.is_file(follow_symlinks=False):
                        continue
                    low = ent.name.lower()
                    if not (low.endswith(SCAN_EXT) or
                            any(h in low for h in _SCAN_HINTS)):
                        continue
                    if ent.path in seen:
                        continue
                    seen.add(ent.path)
                    info = probe_kernel(ent.path)
                    if not info:
                        continue
                    if info["usable"]:
                        usable.append(info)
                        if first_hit:
                            say(f"  命中：{info['path']}")
                            q.clear()
                            break
                    else:
                        others.append(info)
                except OSError:
                    continue

    # 带符号的优先：文件大的通常是完整 vmlinux，排前面
    usable.sort(key=lambda x: -x["size"])
    others.sort(key=lambda x: -x["size"])
    say(f"  扫了 {visited} 个条目 / {len(roots)} 个起点 / {time.time() - t0:.1f}s："
        f"可用 {len(usable)} 个，不可用 {len(others)} 个")
    return usable, others


def human_size(n):
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024.0
    return f"{n:.1f} GB"


# ----------------------------------------------------------------------
# 最近用过的内核镜像（记忆）
# ----------------------------------------------------------------------
# 自动扫描只能覆盖常见目录。用户的 vmlinux 常放在任意盘的工作目录里
# （比如 E:\BOOX\leaf5-ghostlock\...），扫不到。所以选过一次就记下来，
# 下次打开直接填上 —— 这是命中率最高的一层「自动」。
def recent_file():
    return os.path.join(
        os.environ.get("LOCALAPPDATA", os.path.expanduser("~")),
        "Leaf5RootTool", "recent_kernels.json")


def load_recent(max_n=8):
    """返回仍存在的最近路径，最近的在前面。失效的顺手剔掉。"""
    p = recent_file()
    try:
        with open(p, encoding="utf-8") as f:
            items = json.load(f)
    except Exception:
        return []
    if not isinstance(items, list):
        return []
    alive = []
    for it in items:
        if not isinstance(it, str) or not os.path.isfile(it):
            continue
        if it not in alive:
            alive.append(it)
        if len(alive) >= max_n:
            break
    if alive != items:
        try:
            with open(p, "w", encoding="utf-8") as f:
                json.dump(alive, f, ensure_ascii=False, indent=2)
        except OSError:
            pass
    return alive


def remember_kernel(path):
    """把一个路径提到最近列表最前面。原子写，避免并发时写坏。"""
    if not path:
        return
    path = os.path.abspath(path)
    items = [path] + [x for x in load_recent() if x != path]
    items = items[:8]
    dst = recent_file()
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    tmp = dst + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(items, f, ensure_ascii=False, indent=2)
        os.replace(tmp, dst)
    except OSError:
        pass


def scan_disks(budget=180.0, max_depth=8, log=None, stop=None, first_hit=False):
    """
    全盘扫。常见目录扫不到时才跑。

    只按扩展名/文件名筛，命中才读文件头，所以主要成本在遍历目录本身。
    max_depth 给小一点（6）就是「快扫」，够覆盖 D:\\项目\\固件包\\xxx 这种深度。
    first_hit=True 找到第一个带符号镜像就停 —— 用户要的是「能用」，不是清单。
    """
    roots = []
    if os.name == "nt":
        # 非系统盘先扫：内核镜像几乎都在数据盘，系统盘放在最后当兜底
        for drive in "DEFGHC":
            d = f"{drive}:\\"
            if os.path.isdir(d):
                roots.append(d)
    else:
        roots.append("/")

    def say(s):
        if log:
            log(s)

    say(f"  全盘扫描：{', '.join(roots)}（深度 {max_depth}，最多 {int(budget)} 秒）")
    usable, others = scan_kernels(roots=roots, max_depth=max_depth, budget=budget,
                                  limit=400000, log=log, stop=stop,
                                  first_hit=first_hit)
    return usable, others


# ----------------------------------------------------------------------
# target 仓库（用户适配出来的东西存这儿）
# ----------------------------------------------------------------------
def targets_root():
    return os.path.join(
        os.environ.get("LOCALAPPDATA", os.path.expanduser("~")),
        "Leaf5RootTool", "targets")


def list_targets():
    """返回 [{id, dir, meta}]，按创建时间倒序"""
    root = targets_root()
    if not os.path.isdir(root):
        return []
    out = []
    for name in os.listdir(root):
        d = os.path.join(root, name)
        mf = os.path.join(d, "manifest.json")
        if not os.path.isdir(d) or not os.path.isfile(mf):
            continue
        try:
            with open(mf, encoding="utf-8") as f:
                meta = json.load(f)
        except Exception:
            continue
        meta["id"] = name
        meta["dir"] = d
        out.append(meta)
    out.sort(key=lambda m: m.get("created", ""), reverse=True)
    return out


def save_manifest(tdir, meta):
    os.makedirs(tdir, exist_ok=True)
    with open(os.path.join(tdir, "manifest.json"), "w", encoding="utf-8") as f:
        json.dump(meta, f, ensure_ascii=False, indent=2)


def sym_fingerprint(src_path):
    """
    对"符号来源"算构建指纹，返回可直接塞进 manifest 的 dict。

    只有 kallsyms 文本能算：它的符号顺序是内核按地址排好序后输出到
    /proc/kallsyms 的，同一份构建必然一致，而且地址被 kptr_restrict
    清零也不影响名字序列 —— 这就是无 root 也能认出设备内核的基础。

    ELF 不算（返回 {}）：symtab 的顺序是链接顺序，跟 kallsyms 的地址顺序
    不是一回事，两份值放一起会误判成"不同构建"。
    """
    if not elfsyms.looks_like_kallsyms(src_path):
        return {}
    try:
        import fp as _fp
        st = _fp.fingerprint_kallsyms_file(src_path)
    except Exception:
        return {}
    return {"sym_digest": st["sym_digest"],
            "sym_count": st["kernel_syms"],
            "sym_total": st["total"],
            "sym_module": st["module_syms"]}


def write_sym_fp(src_path, tdir, banner=None):
    """
    把符号指纹存到 targets/<id>/symfp.json。
    install 的时候自动并进 manifest，这样"认出设备"的能力跟着 target 走。

    banner 一起存：同一个符号序列可能对应多个构建（序列一样但代码有改），
    banner 的 commit 是第二个交叉维度，比对时先用它筛。
    """
    meta = sym_fingerprint(src_path)
    if not meta:
        return None
    if banner:
        b = parse_banner(banner)
        meta["kernel_banner"] = banner
        meta["kernel_commit"] = b.get("commit")
        meta["kernel_build"] = b.get("build")
        meta["kernel_version"] = b.get("version")
    os.makedirs(tdir, exist_ok=True)
    p = os.path.join(tdir, "symfp.json")
    with open(p, "w", encoding="utf-8") as f:
        json.dump(meta, f, ensure_ascii=False, indent=2)
    return p


def install_target(tid, so_path, meta):
    """把编好的 preload.so 收进 targets/<tid>/，写 manifest"""
    tdir = os.path.join(targets_root(), tid)
    os.makedirs(tdir, exist_ok=True)
    dst = os.path.join(tdir, "preload.so")
    shutil.copyfile(so_path, dst)
    meta = dict(meta)
    # gen 阶段存下的符号指纹并进来（install 的人不必再传一遍）
    sfp = os.path.join(tdir, "symfp.json")
    if os.path.isfile(sfp):
        try:
            with open(sfp, encoding="utf-8") as f:
                for k, v in json.load(f).items():
                    meta.setdefault(k, v)
        except Exception:
            pass
    meta["so_md5"] = hashlib.md5(open(dst, "rb").read()).hexdigest()
    meta["so_size"] = os.path.getsize(dst)
    meta["created"] = meta.get("created") or time.strftime("%Y-%m-%dT%H:%M:%S")
    save_manifest(tdir, meta)
    return tdir


def pick_payload(dev_fingerprint=None, dev_kernel=None, sym_digest=None):
    """
    给 roottool 用：挑一个 preload.so。
      ① 符号序列哈希完全一致的 target   —— 同一次内核构建，最可信
      ② 设备指纹匹配的 target
      ③ 内核版本串匹配的 target          —— 同版本不同构建，次优
    都没命中返回 (None, None)，调用方退回内置载荷。
    返回 (so_path, target_meta_or_None)
    """
    cands = [m for m in list_targets()
             if os.path.isfile(os.path.join(m["dir"], "preload.so"))]
    if sym_digest:
        for m in cands:
            if m.get("sym_digest") and m["sym_digest"] == sym_digest:
                return os.path.join(m["dir"], "preload.so"), m
    for m in cands:
        if dev_fingerprint and m.get("fingerprint") == dev_fingerprint:
            return os.path.join(m["dir"], "preload.so"), m
    if dev_kernel:
        for m in cands:
            if m.get("kernel") and m["kernel"] == dev_kernel:
                return os.path.join(m["dir"], "preload.so"), m
    return None, None


# ----------------------------------------------------------------------
# 命令行入口（GUI 挂了也能用）
# ----------------------------------------------------------------------
def _cli():
    import argparse
    ap = argparse.ArgumentParser(
        description="把 GhostLock exploit 适配到另一版内核")
    sub = ap.add_subparsers(dest="cmd")

    p1 = sub.add_parser("unpack", help="boot.img → vmlinux.elf")
    p1.add_argument("boot")
    p1.add_argument("-o", "--out", required=True)

    p2 = sub.add_parser("gen", help="vmlinux.elf 或 kallsyms.txt → targets/<id>/target.h")
    p2.add_argument("elf", metavar="src",
                    help="vmlinux.elf 或 /proc/kallsyms 导出的 .txt，两种都吃")
    p2.add_argument("--repo", required=True, help="leaf5-ghostlock 仓库根")
    p2.add_argument("--fingerprint", default="")
    p2.add_argument("--kernel", default="")
    p2.add_argument("--id", default=None)
    p2.add_argument("--force", action="store_true",
                    help="镜像与设备不是同一内核时也照样生成（默认拒绝）")

    p9 = sub.add_parser("banner",
                        help="读镜像里的 linux_banner，跟设备 /proc/version 对一下")
    p9.add_argument("path", help="boot.img / 裸 Image / vmlinux.elf 都行")
    p9.add_argument("--serial", default=None)
    p9.add_argument("--device", default=None,
                    help="设备不在，手工贴 /proc/version 的内容")

    p6 = sub.add_parser("kallsyms",
                        help="从设备现场导出 /proc/kallsyms（有 root 就不用找 vmlinux）")
    p6.add_argument("-o", "--out", default=None)
    p6.add_argument("--serial", default=None, help="多台设备时指定")

    p7 = sub.add_parser("fp",
                        help="无 root 读设备指纹，判断能不能直接用现成载荷")
    p7.add_argument("-o", "--out", default=None, help="指纹包保存路径(.json)")
    p7.add_argument("--serial", default=None)
    p7.add_argument("--no-kallsyms", action="store_true",
                    help="跳过 kallsyms（只取版本串，快但判断力弱）")

    p8 = sub.add_parser("match", help="拿指纹包跟已有 target 比")
    p8.add_argument("fp", help="fp 子命令产出的 .json")

    p3 = sub.add_parser("build", help="编译 preload.so")
    p3.add_argument("target_dir")
    p3.add_argument("--repo", required=True)
    p3.add_argument("--cc", default=None, help="不给就自动找 NDK")
    p3.add_argument("-o", "--out", required=True)

    p4 = sub.add_parser("list", help="列出已适配的 target")
    p5 = sub.add_parser("install", help="把 so 收进 target 仓库")
    p5.add_argument("so")
    p5.add_argument("--id", required=True)
    p5.add_argument("--fingerprint", default="")
    p5.add_argument("--kernel", default="")

    a = ap.parse_args()
    if a.cmd == "unpack":
        print(vmlinux_from_boot(a.boot, a.out, log=print))
    elif a.cmd == "gen":
        tmpl = os.path.join(a.repo, "exploit", "targets", "onyx-leaf5", "target.h")
        print(f"符号来源：{a.elf}")
        src, how, banner = resolve_syms_source(a.elf, log=print)
        if how != "direct":
            print(f"  （自动解包：{how}）")
        if banner:
            print(f"  镜像 banner: {banner}")
            # 设备连着就顺手对一下构建身份。对不上还硬生成，偏移会打偏、
            # 在内核里随机位置崩 —— 宁可在这一步停下。
            ok, out = _adb_read("/proc/version")
            if ok:
                dev_ver = out.decode("latin1").strip()
                v, why, adv = banner_match(banner, dev_ver)
                tag = {"same": "[OK]", "resame": "[!]", "dirty": "[!]",
                       "different": "[X]", "unknown": "[?]"}[v]
                print(f"  {tag} 设备 version: {dev_ver}")
                print(f"      {why}")
                if v != "same":
                    print(f"      {adv}")
                if v == "different" and not a.force:
                    raise AdapterError(
                        "这份镜像不是设备上正在跑的内核，没有生成 target.h。\n"
                        "  换设备当前 boot 分区的镜像；确实要用它就在命令后加 --force")
            else:
                print("  [i] 设备没连，跳过构建身份比对（生成的偏移未经验证）")
        else:
            print("  [!] 读不到 linux_banner —— 这个文件可能不是完整内核镜像")
        offs, miss = elfsyms.extract_offsets(src, tmpl, log=print)
        if miss:
            print(f"[i] {len(miss)} 个宏在内核里没有同名符号（多为硬编码槽位，正常）")
        tid = a.id or suggest_id(a.fingerprint, a.kernel)
        tdir = os.path.join(a.repo, "exploit", "targets", tid)
        unf, nf, diffs = build_target_h(
            tmpl, os.path.join(tdir, "target.h"),
            offs, a.fingerprint, a.kernel, log=print, syms_mode="trust")
        print(f"\n生成 {tdir}/target.h")
        sfp = write_sym_fp(src, tdir, banner)
        if sfp:
            print(f"符号指纹已存 {sfp}"
                  f"（之后同一台设备不用 root 就能被认出来）")
        print(f"待填：{unf}")
        if diffs:
            print(f"提示：{len(diffs)} 个宏与模板原值不同（换版本时属正常）")
        print(f"\n下一步：编辑 target.h 把那 4 个占位符按注释填上，然后")
        print(f"  python adapter.py build \"{tdir}\" --repo \"{a.repo}\" -o out.so")
    elif a.cmd == "build":
        import ndkman
        cc = a.cc or ndkman.install(log=print)[1]
        so, md5, size = compile_preload(
            os.path.join(a.repo, "exploit"), a.target_dir, cc, a.out, log=print)
        print(f"\n{so}  {size} 字节  md5={md5}")
    elif a.cmd == "kallsyms":
        path, st = grab_kallsyms(a.out, a.serial, log=print)
        print(f"\n{path}")
        print(f"  行数 {st['lines']}   符号 {st['syms']}   "
              f"{human_size(st['size'])}   _text 0x{st['text']:016X}")
        print(f"下一步：python adapter.py gen \"{path}\" --repo <仓库根>")
    elif a.cmd == "banner":
        res = banner_check(a.path, serial=a.serial, log=print)
        if not res:
            print("[X] 这个文件里找不到 linux_banner —— 不是完整内核镜像")
            return
        if a.device:
            v, why, adv = banner_match(res["image"], a.device)
            res.update(device=a.device.strip(), verdict=v, why=why, advice=adv)
            print("\n结论：%s\n      %s" % (why, adv))
        elif res["verdict"] == "unknown":
            print("\n" + res["advice"])
        print("\n镜像 banner：%s" % res["image"])
        if res.get("device"):
            print("设备 version：%s" % res["device"])
        if res["verdict"] == "different":
            print("\n[!] 这份镜像不是设备上正在跑的内核，别用它生成 target.h")
            return 5
    elif a.cmd == "fp":
        import fp as fpmod
        f = fpmod.collect(a.serial, log=print, want_kallsyms=not a.no_kallsyms)
        path = fpmod.save(f, a.out)
        print("\n" + fpmod.summary(f))
        res = fpmod.match(f, list_targets())
        print(f"\n结论：{res['why']}")
        print(f"       {res['advice']}")
        print(f"\n指纹包：{path}")
        if res["verdict"] != "same_build":
            print("\n要生成新 target 必须有 root（设备上没有别的地址来源）：")
            print("  python adapter.py kallsyms -o syms.txt")
            print("  python adapter.py gen syms.txt --repo <仓库根>")
    elif a.cmd == "match":
        import fp as fpmod
        f = fpmod.load(a.fp)
        print(fpmod.summary(f))
        res = fpmod.match(f, list_targets())
        print(f"\n结论：{res['why']}")
        print(f"       {res['advice']}")
        if res.get("id"):
            print(f"命中 target：{res['id']}")
    elif a.cmd == "list":
        for m in list_targets():
            print(f"{m['id']}  {m.get('kernel','?'):<42} {m.get('so_md5','?')}")
    elif a.cmd == "install":
        d = install_target(a.id, a.so, {"fingerprint": a.fingerprint,
                                        "kernel": a.kernel})
        print(d)
    else:
        ap.print_help()


if __name__ == "__main__":
    _cli()
