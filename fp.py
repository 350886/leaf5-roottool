# -*- coding: utf-8 -*-
"""
fp.py — 无 root 条件下的内核指纹采集与匹配。

背景约束：目标机拿不到任何外部文件，全部信息只能来自设备本身。
设备没 root 时，能读的东西有限，但有一个被低估的：

    /proc/kallsyms 在 kptr_restrict=1 时，地址列全是 0000000000000000，
    但**符号名和排列顺序是完整的**（内核只隐藏地址，不裁剪名字）。

    符号名序列对一次内核构建极其敏感：少一个 CONFIG_*、换一个编译器、
    改一行内核代码，序列都会变。所以「符号名序列的 sha256」是一个
    几乎不会碰撞的构建指纹，而且**零权限**就能取。

能回答的唯一问题：
    这台设备的内核，是不是我们已经有 target 的那一个？
      · 是     → 直接用现成的 preload.so，不需要 root、不需要重编
      · 不是   → 必须先把设备 root 起来（dd boot / 读全地址 kallsyms），否则无从适配

刻意不承诺的：
    没 root 时反推绝对地址。kallsyms 在地址清零后只剩顺序，没有间隔信息，
    数学上不足以恢复地址。硬猜出来的偏移只会让内核在随机位置崩。
    所以这里只做"认不认得出来"，不做"猜不猜得出"。

作者注：`/proc/kallsyms` 里的模块符号（第 4 列是 `[module_name]`）随加载状态
随时变化，算指纹时必须排除，否则同一台设备重启两次指纹就不一样了。
"""

import hashlib
import json
import os
import re
import shutil
import subprocess
import time

FP_VERSION = 1

# 这些文件在没有 root 时通常可读（读不到就跳过，不当作错误）
_PROC_FILES = [
    ("version",       "/proc/version"),
    ("cmdline",       "/proc/cmdline"),
    ("kptr_restrict", "/proc/sys/kernel/kptr_restrict"),
    ("randomize_va",  "/proc/sys/kernel/randomize_va_space"),
    ("modules",       "/proc/modules"),
    ("cpuinfo",       "/proc/cpuinfo"),
    ("filesystems",   "/proc/filesystems"),
    ("mounts",        "/proc/mounts"),
    ("zoneinfo",      "/proc/zoneinfo"),
    ("sys_cpu",       "/sys/devices/system/cpu/possible"),
    ("build_prop",    "/system/build.prop"),
    ("vendor_prop",   "/vendor/build.prop"),
]

_MODULE_DIRS = ["/vendor/lib/modules", "/system/lib/modules",
                "/vendor_dlkm/lib/modules", "/system_dlkm/lib/modules"]

# getprop 里跟内核/构建相关的键
_PROP_KEYS = [
    "ro.product.model", "ro.product.device", "ro.product.name",
    "ro.build.display.id", "ro.build.version.release",
    "ro.build.version.sdk", "ro.build.fingerprint", "ro.build.date.utc",
    "ro.board.platform", "ro.hardware", "ro.boot.hardware",
    "ro.boot.slot_suffix", "ro.boot.verifiedbootstate", "ro.boot.flash.locked",
    "ro.kernel.version", "ro.kernel.android.checkjni",
    "ro.vendor.build.fingerprint", "ro.system.build.fingerprint",
]

_SEP = "@@@FP@@@"


class FpError(Exception):
    pass


def adb_path():
    """内嵌 adb 优先，退回 PATH。"""
    base = os.environ.get("_MEIPASS") or os.path.dirname(
        os.path.abspath(__file__))
    p = os.path.join(base, "assets", "adb", "adb.exe")
    if os.path.isfile(p):
        return p
    return shutil.which("adb") or "adb"


def _run(args, timeout=60, env=None):
    """跑一条 adb 命令，返回 (ok, bytes)。失败不抛，由调用方决定是否致命。"""
    try:
        r = subprocess.run(args, capture_output=True, timeout=timeout,
                           env=env,
                           creationflags=getattr(
                               subprocess, "CREATE_NO_WINDOW", 0))
    except subprocess.TimeoutExpired:
        return False, b""
    except OSError:
        return False, b""
    return r.returncode == 0, (r.stdout or b"")


def _txt(b):
    return (b or b"").decode("utf-8", "replace")


def pick_serial(adb, wanted=None, env=None):
    """挑一台 device 状态的设备，返回 serial。"""
    ok, out = _run([adb, "devices"], env=env)
    if not ok:
        raise FpError("adb devices 执行失败，adb 可能没就绪")
    devs = [l.split("\t")[0] for l in _txt(out).splitlines()[1:]
            if "\tdevice" in l]
    if not devs:
        raise FpError("没有处于 device 状态的设备。\n"
                      "  手机插 USB、开「USB 调试」，在手机上点允许调试")
    if wanted:
        if wanted not in devs:
            raise FpError("指定的设备 %s 不在线，在线的是：%s"
                          % (wanted, ", ".join(devs)))
        return wanted
    if len(devs) > 1:
        raise FpError("连了多台设备（%s），先只插一台，或用 serial 指定"
                      % ", ".join(devs))
    return devs[0]


# ----------------------------------------------------------------------
# kallsyms 指纹
# ----------------------------------------------------------------------
def parse_kallsyms(text):
    """
    拆 kallsyms 文本，返回 (内核符号名列表, 统计 dict)。

    排除模块符号：`ffff.. t foo [binder_linux]` 这种，名字随加载状态变。
    只留内核自身的符号，指纹才稳定。
    """
    names = []
    total = 0
    zeroed = 0
    mods = 0
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) < 3:
            continue
        total += 1
        if len(parts) >= 4 and parts[3].startswith("["):
            mods += 1
            continue
        addr = parts[0]
        if not re.match(r"^[0-9a-fA-F]{8,16}$", addr):
            continue
        if addr.strip("0") == "":       # 全 0 = 地址被 kptr_restrict 清了
            zeroed += 1
        names.append(parts[2])
    return names, {"total": total, "module_syms": mods,
                   "kernel_syms": len(names), "zeroed": zeroed}


def digest_names(names):
    """
    符号名序列的 sha256。

    为什么带上顺序而不是排序后求哈希：顺序本身也是构建产物
    （链接顺序、汇编文件顺序），排序会丢掉这部分信息。
    """
    h = hashlib.sha256()
    for n in names:
        h.update(n.encode("utf-8", "replace"))
        h.update(b"\n")
    return h.hexdigest()


def fingerprint_kallsyms_file(path):
    """从一份 kallsyms 文件算指纹（离线用，也用于自检）。"""
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        text = f.read()
    names, st = parse_kallsyms(text)
    st["sym_digest"] = digest_names(names)
    # 前 32 个符号名留一份样本，人工核对用
    st["head"] = names[:32]
    return st


# ----------------------------------------------------------------------
# 采集
# ----------------------------------------------------------------------
def collect(serial=None, adb=None, log=None, want_kallsyms=True, env=None):
    """
    无 root 采集设备指纹，返回 dict（可直接 json 存盘）。

    全程不用 su。任何一项读不到就跳过 —— 不同厂商开放度差别很大，
    缺项不影响主判据（符号序列），只是少一点佐证。
    """
    def say(s):
        if log:
            log(s)

    adb = adb or adb_path()
    serial = pick_serial(adb, serial, env)
    base = [adb, "-s", serial]
    say(f"  设备 {serial}")

    fp = {
        "fp_version": FP_VERSION,
        "collected": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "serial": serial,
        "root": False,
    }

    # 1) 一批小文件，用分隔符一次性拉回（走 exec-out，避免 shell 的 CRLF 与编码转换）
    parts = []
    for key, path in _PROC_FILES:
        parts.append(f"echo '{_SEP}{key}'; cat {path} 2>/dev/null")
    script = "; ".join(parts)
    ok, out = _run(base + ["exec-out", "sh", "-c", script], timeout=90, env=env)
    if not ok:
        raise FpError("读取 /proc 失败，adb 通道不通（换根线或重插试试）")
    chunks = _txt(out).split(_SEP)
    raw = {}
    for c in chunks[1:]:
        nl = c.find("\n")
        if nl < 0:
            continue
        raw[c[:nl].strip()] = c[nl + 1:]
    fp["raw"] = {k: (v.strip() if len(v) < 4000 else v[:4000])
                 for k, v in raw.items()}
    say(f"  读到 {len(raw)}/{len(_PROC_FILES)} 个 /proc 项")

    # 2) 内核版本串："Linux version 4.19.157-perf-g3d47a6619220-dirty ..."
    ver_line = (raw.get("version") or "").strip()
    m = re.search(r"Linux version (\S+)", ver_line)
    fp["kernel_ver"] = m.group(1) if m else ""
    m = re.search(r"#(\d+)", ver_line)
    fp["kernel_build_no"] = int(m.group(1)) if m else 0
    # 构建时间戳：不同构建几乎不会撞，比版本串更能区分
    m = re.search(r"\((\w+@[\w.-]+)\).*?(\w{3} \w{3} \d+ \d+:\d+:\d+ \w+ \d{4})",
                  ver_line)
    fp["builder"] = m.group(1) if m else ""
    fp["build_time"] = m.group(2) if m else ""

    # 3) 属性
    ok, out = _run(base + ["exec-out", "getprop"], timeout=60, env=env)
    props = {}
    if ok:
        for line in _txt(out).splitlines():
            mm = re.match(r"^\[([^\]]+)\]: \[(.*)\]$", line.strip())
            if mm and mm.group(1) in _PROP_KEYS:
                props[mm.group(1)] = mm.group(2)
    fp["props"] = props
    fp["model"] = props.get("ro.product.model", "")
    fp["build_id"] = props.get("ro.build.display.id", "")
    say(f"  型号 {fp['model'] or '?'}   构建 {fp['build_id'] or '?'}")

    # 4) 已加载模块名（配置指纹的旁证）
    mods = []
    for line in (raw.get("modules") or "").splitlines():
        t = line.split()
        if t:
            mods.append(t[0])
    fp["loaded_modules"] = sorted(mods)

    # 5) 模块目录清单（能看到厂商编了哪些 .ko，反映 CONFIG）
    ko = {}
    for d in _MODULE_DIRS:
        ok, out = _run(base + ["exec-out", "sh", "-c",
                              f"ls -1 {d} 2>/dev/null"], timeout=30, env=env)
        if ok and out.strip():
            ko[d] = sorted(x for x in _txt(out).split()
                           if x.endswith(".ko"))
    fp["module_files"] = ko
    n_ko = sum(len(v) for v in ko.values())
    if n_ko:
        say(f"  模块文件 {n_ko} 个")

    # 6) kallsyms —— 主判据
    if want_kallsyms:
        say("  读 /proc/kallsyms（12 万行左右，取符号名序列）")
        ok, out = _run(base + ["exec-out", "cat", "/proc/kallsyms"],
                       timeout=180, env=env)
        if not ok or len(out) < 100 * 1024:
            fp["sym"] = {"error": "读取失败或内容过短，可能被 SELinux 拦了"}
            say("  [!] kallsyms 读不到，指纹只剩版本串可用")
        else:
            text = _txt(out)
            names, st = parse_kallsyms(text)
            st["sym_digest"] = digest_names(names)
            st["head"] = names[:32]
            del names
            fp["sym"] = st
            say(f"  符号 {st['kernel_syms']} 个（模块 {st['module_syms']}），"
                f"零地址 {st['zeroed']}")
            if st["zeroed"] == 0:
                fp["root"] = True
                say("  地址未被隐藏 —— 这份 kallsyms 可以直接拿去生成 target.h")

    # 7) 总指纹：把几项拼起来再哈希，给人一个短标识
    seed = "|".join([
        fp.get("kernel_ver", ""), fp.get("build_time", ""),
        str(fp.get("sym", {}).get("sym_digest", "")),
        str(fp.get("sym", {}).get("kernel_syms", "")),
    ])
    fp["id"] = hashlib.sha256(seed.encode()).hexdigest()[:16]
    return fp


# ----------------------------------------------------------------------
# 匹配
# ----------------------------------------------------------------------
def match(fp, targets):
    """
    拿指纹跟已有 target 清单比，返回结论 dict：
      verdict: same_build | same_version | different | no_target
      id:      命中的 target id（没命中为 None）
      why:     一句话说明
      advice:  下一步该做什么

    判据优先级：
      1. sym_digest 完全相等 —— 同一次内核构建，偏移必然一致，可以直接用
      2. kernel_ver 相等 —— 同版本不同构建，偏移**可能**不同，需要 root 核实
      3. 都不等 —— 完全陌生的内核，必须 root 后重新适配
    """
    sym = fp.get("sym") or {}
    dg = sym.get("sym_digest", "")
    n = sym.get("kernel_syms", 0)
    ver = fp.get("kernel_ver", "")

    if not targets:
        return {"verdict": "no_target", "id": None,
                "why": "工具里还没有任何适配过的内核",
                "advice": "先把设备 root 起来，再从设备读 kallsyms 生成第一份 target"}

    if dg:
        for m in targets:
            if m.get("sym_digest") and m["sym_digest"] == dg:
                return {"verdict": "same_build", "id": m["id"],
                        "why": f"符号名序列完全一致（{n} 个符号）—— "
                               f"这就是 target「{m['id']}」对应的同一次内核构建",
                        "advice": "直接用这份 preload.so，不需要 root、不需要重编"}

    if ver:
        for m in targets:
            if m.get("kernel") and m["kernel"] == ver:
                return {"verdict": "same_version", "id": m["id"],
                        "why": f"内核版本串相同（{ver}），但符号序列不同"
                               f"（本机 {n} 个）—— 同版本的不同构建",
                        "advice": "偏移可能不同，先用「从设备读符号」核实；"
                                  "没 root 的话不要硬试，内核会 panic"}

    same_n = [m for m in targets
              if n and m.get("sym_count") and m["sym_count"] == n]
    if same_n:
        return {"verdict": "different", "id": same_n[0]["id"],
                "why": f"版本串不同（{ver}），但符号数一样（{n} 个），"
                       f"可能只是改了版本串的重新打包",
                "advice": "有 root 就跑「从设备读符号」核对；"
                          "没 root 不要试，概率不高"}

    return {"verdict": "different", "id": None,
            "why": f"内核版本串 {ver or '?'}，符号 {n or '?'} 个 —— 没有匹配的 target",
            "advice": "这是陌生内核。设备必须先 root，"
                      "再用「从设备读符号」拉完整 kallsyms 生成新 target"}


# ----------------------------------------------------------------------
# 存读
# ----------------------------------------------------------------------
def save(fp, path=None):
    path = path or os.path.join(
        os.getcwd(), "device-fp-%s.json" % time.strftime("%Y%m%d-%H%M%S"))
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(fp, f, ensure_ascii=False, indent=2)
    return path


def load(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def summary(fp):
    """给人看的一段摘要"""
    sym = fp.get("sym") or {}
    lines = [
        f"  型号      {fp.get('model') or '?'}",
        f"  系统      {fp.get('build_id') or '?'}",
        f"  内核      {fp.get('kernel_ver') or '?'}"
        f"（build #{fp.get('kernel_build_no') or '?'}）",
        f"  构建时间  {fp.get('build_time') or '?'}",
        f"  符号      {sym.get('kernel_syms', '?')} 个"
        f"（模块 {sym.get('module_syms', 0)} 个）",
        f"  地址可见  {'是' if sym.get('zeroed') == 0 and sym.get('kernel_syms')
                        else '否（kptr_restrict 隐藏）'}",
        f"  序列哈希  {(sym.get('sym_digest') or '无')[:32]}",
        f"  指纹 id   {fp.get('id', '?')}",
    ]
    return "\n".join(lines)


def _cli():
    import argparse
    ap = argparse.ArgumentParser(
        description="无 root 采集设备内核指纹，判断能不能直接用现成载荷")
    ap.add_argument("-o", "--out", default=None, help="指纹包保存路径(.json)")
    ap.add_argument("--serial", default=None)
    a = ap.parse_args()

    fp = collect(a.serial, log=print)
    path = save(fp, a.out)
    print("\n" + summary(fp))
    print(f"\n已保存：{path}")
    sym = fp.get("sym") or {}
    if sym.get("zeroed", 0) > 0:
        print("\n地址被隐藏。想直接生成 target.h 需要 root：")
        print("  python adapter.py kallsyms -o syms.txt")
    else:
        print("\n地址可见，可以直接生成 target.h：")
        print(f"  python adapter.py kallsyms -o syms.txt")


if __name__ == "__main__":
    _cli()
