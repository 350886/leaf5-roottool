# -*- coding: utf-8 -*-
"""
9008（EDL）只读导出。不需要 root，不需要 OTA 包，不需要外部 edl 工具。

**v2 改动（2026-10-30）**：原来是子进程调外部 `edl.py` + 外部 python venv。
打包成单 EXE 后这条路径是死的 —— EXE 里没有 edl.py，fallback 到
`sys.executable` 就是 EXE 自己，subprocess 一调就重跑 GUI。现在改成
`edllink.Session`（库化 edlclient）在**本进程内**跑：
  · 一条 9008 连接干完全部活（printgpt → r → reset），不再断开重连
    （edl 跑完命令不关 USB 句柄，第二次 connect 必然 errno 13）
  · programmer 从内置 assets 出，不依赖外部目录
  · 缺 WinUSB 驱动时自动拉起内置 Zadig（drivers.py）

对外接口保持原样：`dump_boot()` 仍返回 dict(path, partition, size, slot, gpt)。
"""
import hashlib
import os
import re
import shutil
import subprocess
import sys
import time

import drivers
import edllink

CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)


class EdlError(Exception):
    pass


def _tool_root():
    """工具根目录。EXE 里是 EXE 所在目录（持久数据放这儿），源码里是脚本目录。"""
    if getattr(sys, "frozen", False):
        return os.path.dirname(os.path.abspath(sys.executable))
    return os.path.dirname(os.path.abspath(__file__))


# ----------------------------------------------------------------------
# 资源定位
# ----------------------------------------------------------------------
def find_loader():
    """
    firehose programmer。打包后在 _MEIPASS/assets，源码在 assets/ 或 ../loaders。
    """
    return edllink.loader_path()


def env_report():
    """给界面/日志用的一句话状态。"""
    ld = find_loader()
    lib = "libusb 未注入"
    try:
        # _prepare() 会把 libusb 目录塞进 DLL 搜索路径，成功就能 import usb.core
        edllink._prepare()
        import usb.core  # noqa: F401
        lib = "libusb 就绪"
    except Exception as e:
        lib = "libusb %s" % type(e).__name__
    return "programmer %s，%s，edl 内置" % (
        (os.path.basename(ld) if ld else "未找到"), lib)


# ----------------------------------------------------------------------
# adb 侧：槽位与状态
# ----------------------------------------------------------------------
def adb_path():
    """
    内置 adb 优先。**打包后 assets 在 _MEIPASS 里，不在 EXE 同级目录** ——
    原来只看 _tool_root()/assets 是错的，会静默回退到 PATH 里的 adb，
    新机器上没装 adb 就直接失败（表现成"没有检测到设备"，误导性极强）。
    所以顺序是：_MEIPASS/assets/adb → EXE 同级 assets/adb（允许用户覆盖）→ PATH。
    """
    return _adb_path()


def _adb_path():
    for p in (os.path.join(edllink.assets_dir(), "adb",
                           "adb.exe" if os.name == "nt" else "adb"),
              os.path.join(_tool_root(), "assets", "adb",
                           "adb.exe" if os.name == "nt" else "adb")):
        if os.path.isfile(p):
            return _stage_adb(p)
    return shutil.which("adb") or "adb"


def _stage_adb(src):
    """
    adb 首次执行会拉起常驻 adb server，server 持有 adb.exe 句柄。
    从 _MEIPASS 跑的话，PyInstaller 退出时删不掉临时目录，进程卡死不退。
    先拷到 %LOCALAPPDATA%\\Leaf5RootTool\\adb\\ 再执行，只拷一次。
    """
    if "_MEI" not in src.upper():
        return src
    base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
    dst_dir = os.path.join(base, "Leaf5RootTool", "adb")
    try:
        os.makedirs(dst_dir, exist_ok=True)
        src_dir = os.path.dirname(src)
        for n in os.listdir(src_dir):
            s = os.path.join(src_dir, n)
            d = os.path.join(dst_dir, n)
            if os.path.isfile(s) and (not os.path.isfile(d)
                                      or os.path.getsize(d) != os.path.getsize(s)):
                shutil.copy2(s, d)
        return os.path.join(dst_dir, os.path.basename(src))
    except Exception:
        return src


def adb_run(args, timeout=30, env=None):
    try:
        r = subprocess.run([android_adb()] + args, capture_output=True,
                           timeout=timeout, env=env,
                           creationflags=CREATE_NO_WINDOW)
    except (subprocess.TimeoutExpired, OSError):
        return None
    return (r.stdout or b"") + (r.stderr or b"") if r.returncode == 0 else (r.stdout or b"")


_ADB_CACHE = {}


def android_adb():
    if "p" not in _ADB_CACHE:
        _ADB_CACHE["p"] = _adb_path()
    return _ADB_CACHE["p"]


def adb_devices(env=None):
    out = adb_run(["devices"], env=env)
    if not out:
        return []
    txt = out.decode("utf-8", "replace")
    return [l.split("\t")[0] for l in txt.splitlines()[1:] if "\tdevice" in l]


def slot_suffix(env=None, serial=None):
    """
    当前运行在哪个槽。**不需要 root**，两个来源交叉验证：
      · getprop ro.boot.slot_suffix  →  "_a" / "_b"
      · /proc/cmdline 里的 androidboot.slot_suffix=_a
    拿不到返回 None（非 A/B 设备就是 None，正常）。
    """
    base = ["-s", serial] if serial else []

    def _read_slot():
        out = adb_run(base + ["shell", "getprop", "ro.boot.slot_suffix"], env=env)
        if out:
            s = out.decode("utf-8", "replace").strip()
            if s in ("_a", "_b"):
                return s
        out = adb_run(base + ["exec-out", "cat", "/proc/cmdline"], env=env)
        if out:
            m = re.search(rb"androidboot\.slot_suffix=(_[ab])", out)
            if m:
                return m.group(1).decode()
        return None

    s = _read_slot()
    if s:
        return s
    # 第一次经常撞在 adb daemon 冷启动上：`adb shell` 打出
    # "daemon not running; starting now" 就返回，命令本身没执行、stdout 是空的。
    # daemon 起来后再读一次就好 —— 不重试的话，整个 dump 会误判成「非 A/B 设备」
    # 而退回 GPT Active 标志（同一份代码在 EXE 里能用、源码里读不到就是这个）。
    time.sleep(0.6)
    return _read_slot()


def _has_edl_device():
    """05C6:9008 在不在。走 SetupAPI，不依赖驱动是否绑好。"""
    try:
        nodes = edllink.find_9008()
        return bool(nodes)
    except Exception:
        return None


def reboot_to_edl(env=None, serial=None, log=None):
    """adb reboot edl。设备会重启进入下载模式（屏幕黑）。"""
    def say(x):
        if log:
            log(x)

    base = ["-s", serial] if serial else []
    say("  adb reboot edl（设备会黑屏重启，属正常）")
    # 设备一进下载模式 adbd 就消失，这条命令拿不到干净的 rc=0；
    # "error: device not found" 反而是成功信号，"Operation not permitted" 才是被拒。
    try:
        r = subprocess.run([android_adb()] + base + ["reboot", "edl"],
                           capture_output=True, timeout=30, env=env,
                           creationflags=CREATE_NO_WINDOW)
        err = ((r.stdout or b"") + (r.stderr or b"")).decode("utf-8", "replace")
    except (subprocess.TimeoutExpired, OSError) as e:
        err = str(e)

    if "not permitted" in err.lower():
        say("  [!] reboot edl 被系统拒绝（Operation not permitted）")
        say("      Android 侧的 EDL 入口被固件关掉了，改走硬件组合键：")
        say("      关机 → 按住音量上+下 → 插 USB")
        return False
    if err.strip() and "not found" not in err.lower():
        say("  adb 回显：%s" % err.strip()[:120])

    ok, waited = edllink.wait_9008(limit=30.0)
    if ok:
        say("  已进入 9008（%.1fs）" % waited)
        return True
    say("  [!] 30 秒内总线没出现 9008 节点")
    return False


def _ensure_edl(log=None, allow_driver=True):
    """
    确保设备在 9008 且驱动可用。返回 True 表示可以往下读。
    五种状态对应五种动作（见 usbtrace.verdict）。
    """
    def say(x):
        if log:
            log(x)

    if _has_edl_device() is True:
        if drivers.state().get("usable"):
            say("  9008 在线，驱动就绪")
            return True
        say("  9008 在线，但驱动不可用")
        return _fix_driver(log=log) if allow_driver else False

    if not adb_devices():
        say("  [!] adb 和 9008 都没有设备")
        return False
    reboot_to_edl(log=log)
    if _has_edl_device() is True:
        if drivers.state().get("usable"):
            return True
        return _fix_driver(log=log) if allow_driver else False
    return False


def _fix_driver(log=None):
    """缺 WinUSB：拉起内置 Zadig，等驱动就绪。"""
    def say(x):
        if log:
            log(x)

    st = drivers.state()
    say("  " + drivers.summary(st))
    if st.get("usable"):
        return True
    p, how = drivers.find_zadig()
    if not p:
        say("  [!] 没找到内置 zadig.exe（%s）" % how)
        return False
    say("  设备已经在下载模式里等着了 —— 不要拔线、不要重启、不要长按电源。")
    for line in drivers.steps_text().splitlines():
        say("  " + line)
    ok, msg = drivers.launch_zadig(p, log=say)
    if not ok:
        say("  [!] 拉起 Zadig 失败：%s" % msg)
        return False
    say("  已拉起 Zadig，等驱动装好（最多 240 秒）…")
    done, used, st2 = drivers.wait_ready(
        seconds=240.0,
        on_tick=lambda el, s2: say("    已等 %.0fs：%s" % (el, drivers.summary(s2)))
        if int(el) and int(el) % 30 == 0 else None)
    if done:
        say("  驱动就绪（%.0fs）" % used)
        return True
    say("  [!] 等 %.0fs 仍未就绪：%s" % (used, drivers.summary(st2)))
    return False


# ----------------------------------------------------------------------
# GPT 解析
# ----------------------------------------------------------------------
# edl 的实际输出（edlclient/Library/gpt.py:418）：
#   "boot_b:              Offset 0x0000000040000000, Length 0x0000000004000000, ..., Active True"
# 分区名右补空格到 20 列、名字后带冒号。冒号做可选，防不同版本格式差异。
GPT_RE = re.compile(
    r"^\s*([^\s:]+):?\s+Offset\s+(0x[0-9a-fA-F]+),"
    r"\s+Length\s+(0x[0-9a-fA-F]+)"
    r"(?:.*?Active\s+(True|False))?", re.M)


def parse_gpt(text):
    parts = {}
    for m in GPT_RE.finditer(text or ""):
        name = m.group(1)
        if name in ("GPT", "Parsing", "Table"):
            continue
        parts[name] = dict(
            offset=int(m.group(2), 16),
            length=int(m.group(3), 16),
            active=(m.group(4) == "True") if m.group(4) else None,
        )
    return parts


# ----------------------------------------------------------------------
# 库化 edl：一条连接干完
# ----------------------------------------------------------------------
def _emit_factory(log, quiet=False):
    """把 edl 的输出行转给 log。quiet=True 时分区行不逐条打（太多）。"""
    def emit(t):
        if not log:
            return
        if quiet and "Offset" in t:
            return
        log("  " + t)
    return emit


def printgpt(loader=None, log=None, timeout=120):
    """
    单独读分区表（CLI 用）。返回 {分区名: dict(offset, length, active)}。

    设备不在 9008 时自己送进去 —— 以前这里直接 open()，设备在系统里会
    报「没建立起 firehose 会话」，看起来像功能坏了，其实就是没进下载模式。
    """
    if not _ensure_edl(log=log, allow_driver=True):
        raise EdlError("设备没能进入可用的 9008 状态")
    sess = edllink.Session(loader=loader or find_loader())
    buf = []
    try:
        sess.open(on_line=lambda t: (buf.append(t), log and log("  " + t)),
                  timeout=90)
        sess.printgpt(on_line=lambda t: (buf.append(t),
                                         log and not _skip(t) and log("  " + t)),
                      timeout=timeout)
    finally:
        try:
            sess.reset()
        except Exception:
            pass
        sess.close()
    parts = parse_gpt("\n".join(buf))
    if not parts:
        raise EdlError("printgpt 没解析出分区表。原始输出：\n"
                       + "\n".join(buf[-40:]))
    return parts


def _skip(t):
    return "Offset" in t


def read_partition(loader, name, out_path, log=None, timeout=300):
    """
    单独读一个分区（CLI 用）。

    先 printgpt 拿到它的起始扇区，再按 4MB 分块读。整条 read 命令一路读到
    底的话，中途撞 EPIPE 就会数据错位（长度能凑够、内容不对），分块能把
    损失限制在一块里，重读那一块就干净了。小分区（vbmeta 64KB）不受影响。
    """
    if not _ensure_edl(log=log, allow_driver=True):
        raise EdlError("设备没能进入可用的 9008 状态")
    sess = edllink.Session(loader=loader or find_loader())
    buf = []
    try:
        sess.open(timeout=90)
        place = expect = None
        try:
            sess.printgpt(on_line=buf.append, timeout=90)
            e = parse_gpt("\n".join(buf)).get(name)
            if e:
                place = (0, e["offset"] // 512, e["length"] // 512)
                expect = e["length"]
                if log:
                    log("  分区 %s：offset 0x%X，%d 字节" % (name, e["offset"], e["length"]))
        except Exception:
            pass
        if place is None and log:
            log("  [!] 分区表里没找到 %s，退回单条 read（大分区可能读不满）" % name)
        sess.read(name, out_path, on_progress=None, timeout=timeout,
                  place=place, expect=expect)
    finally:
        try:
            sess.reset()
        except Exception:
            pass
        sess.close()
    if not os.path.isfile(out_path) or os.path.getsize(out_path) == 0:
        raise EdlError("读 %s 失败（文件没生成）" % name)
    return os.path.getsize(out_path)


def reset(loader=None, log=None):
    """退出下载模式。读失败也要调，否则设备一直黑着。"""
    try:
        sess = edllink.Session(loader=loader or find_loader())
        try:
            sess.open(timeout=60)
            sess.reset()
        finally:
            sess.close()
    except Exception:
        pass


# ----------------------------------------------------------------------
# 一站式：定槽位 → 一条连接读 GPT + 读分区 + reset
# ----------------------------------------------------------------------
def dump_boot(out_dir, prefer_slot=None, log=None, env=None, serial=None,
              timeout_gpt=120, timeout_read=300, allow_driver=True,
              extra_parts=("vbmeta",)):
    """
    把设备**当前运行槽**的 boot 分区读出来。

    prefer_slot 给 "_a"/"_b" 就强制读那个；不给就按这个顺序定：
      ① adb 还能用 → 读 slot_suffix（最准，是运行时事实）
      ② 已经进 9008 了 → 用 GPT 里 boot_* 的 Active 标志
      ③ 都没有 → 读 boot_b

    返回 dict(path, partition, size, slot, gpt)。
    """
    def say(x):
        if log:
            log(x)

    loader = find_loader()
    if not loader:
        raise EdlError("找不到 firehose programmer（*_fhprg.bin）。\n"
                       "  正常安装包里 assets\\ 下应该有 lito_op_n10_fhprg.bin")
    say("  " + env_report())

    os.makedirs(out_dir, exist_ok=True)

    # ① 先定槽位（adb 还活着的时候最准）
    slot = prefer_slot
    if not slot:
        slot = slot_suffix(env=env, serial=serial)
        if slot:
            say("  设备 slot_suffix = %s（当前运行槽）" % slot)
        else:
            say("  [!] 读不到 slot_suffix（非 A/B 设备，或 adb 已断开）")

    # ② 不在 9008 / 驱动不可用 → 送进去并装驱动
    if not _ensure_edl(log=log, allow_driver=allow_driver):
        raise EdlError(
            "设备没能进入可用的 9008 状态。\n"
            "  逐项查：\n"
            "    1. usb 线 / 换后置 USB 口（别过 hub）\n"
            "    2. 设备开机状态、USB 调试已开、屏幕弹窗点了「允许」\n"
            "    3. 缺 WinUSB 驱动 → 工具会自己拉 Zadig，没拉起来说明本机缺 zadig\n"
            "    4. 都不行走硬件组合键：关机 → 按住音量上+下 → 插 USB")

    sess = edllink.Session(loader=loader)
    buf = []
    gpt = {}
    extra = {}
    out = None
    size = 0
    name = None

    def on_line(t):
        buf.append(t)
        if not _skip(t):
            say("  " + t)

    try:
        say("  连接 9008…")
        t0 = time.time()
        sess.open(on_line=on_line, timeout=90)
        say("  已连接（%.1fs）" % (time.time() - t0))

        # ③ 分区表
        say("  读 GPT 分区表")
        sess.printgpt(on_line=on_line, timeout=timeout_gpt)
        gpt = parse_gpt("\n".join(buf))
        if gpt:
            say("  分区 %d 个" % len(gpt))
            boots = sorted(n for n in gpt if re.match(r"^boot_[ab]$", n))
            for n in boots:
                say("    %-8s %10d 字节%s" % (
                    n, gpt[n]["length"],
                    "  ← 活动槽" if gpt[n]["active"] else ""))
        else:
            # 解析不到不等于读不了：edl 的 r 命令自己会查 GPT 找分区
            say("  [!] 分区表没解析到（不阻断：读取时 edl 自己会查 GPT）")
        boots = sorted(n for n in gpt if re.match(r"^boot_[ab]$", n))

        # ④ 选分区
        if slot and ("boot" + slot) in gpt:
            name = "boot" + slot
            say("  按 slot_suffix 选 %s" % name)
        elif boots:
            act = [n for n in boots if gpt[n]["active"]]
            if len(act) == 1:
                name = act[0]
                say("  按 GPT Active 标志选 %s" % name)
            else:
                name = boots[-1]
                say("  [!] 分不清活动槽，退回 %s" % name)
        elif "boot" in gpt:
            name = "boot"
        elif slot:
            name = "boot" + slot
            say("  [!] 分区表没拿到，按 slot_suffix 直接试 %s" % name)
        else:
            name = "boot_b"
            say("  [!] 分区表和槽位都没拿到，按经验试 boot_b")

        out = os.path.join(out_dir, "%s.img" % name)

        # 空间检查（唯一会卡住读取的现场问题）
        free = shutil.disk_usage(os.path.dirname(os.path.abspath(out))).free
        need = int(gpt.get(name, {}).get("length", 128 * 1048576) * 1.2)
        if free < need:
            raise EdlError("磁盘空间不够：%s 只剩 %.1f MB，需要约 %.1f MB"
                           % (os.path.dirname(out), free / 1048576.0,
                              need / 1048576.0))

        # ⑤ 读取
        say("  读取 %s → %s" % (name, out))
        t1 = time.time()
        # place/expect：设备端中途少发时要按扇区补读，光给分区名补不了。
        # GPT 里的 Offset/Length 都是字节，扇区按 512 折算。
        place = None
        expect = gpt.get(name, {}).get("length")
        if expect:
            place = (0, gpt[name]["offset"] // 512, expect // 512)
        sess.read(name, out, on_line=on_line, timeout=timeout_read,
                  place=place, expect=expect)
        size = os.path.getsize(out)
        dt = max(time.time() - t1, 0.001)
        say("  完成 %d 字节 / %.1fs / %.1f MB/s"
            % (size, dt, size / 1048576.0 / dt))
        if expect and size != expect:
            say("  [!] 大小与分区表不符：文件 %d，分区 %d" % (size, expect))

        # ⑥ 顺带读 vbmeta（同一个连接里，不再重连）
        #
        # 为什么要它：改了 boot 之后 AVB 校验会失败。bootloader 已解锁时
        # （verifiedbootstate=orange / flash.locked=0）系统不强制校验，所以
        # root 流程本身不依赖它；但它是"改之前的回滚参照" —— 出问题能把
        # boot+vbmeta 一起刷回原厂状态，而不是只有 boot 半套。
        # 64 KB，代价可忽略；读失败只警告，不阻断。
        for base in (extra_parts or ()):
            cand = None
            if slot and (base + slot) in gpt:
                cand = base + slot
            elif base in gpt:
                cand = base
            if not cand:
                say("  [!] 分区表里没有 %s，跳过" % base)
                continue
            ep = os.path.join(out_dir, "%s.img" % cand)
            try:
                say("  读取 %s → %s" % (cand, ep))
                eexp = gpt.get(cand, {}).get("length")
                eplace = (0, gpt[cand]["offset"] // 512, eexp // 512) if eexp else None
                sess.read(cand, ep, timeout=120, place=eplace, expect=eexp)
                esz = os.path.getsize(ep)
                extra[cand] = dict(path=ep, size=esz)
                say("    %s  %d 字节" % (cand, esz))
            except Exception as ex:
                say("  [!] %s 读取失败（不影响 boot 主流程）：%s" % (cand, ex))
    finally:
        # 无论成败都要回系统，否则设备一直黑屏停在下载模式
        try:
            say("  reset 回系统")
            sess.reset()
        except Exception:
            pass
        sess.close()

    if not out or not size:
        raise EdlError("没有产出文件。edl 输出：\n" + "\n".join(buf[-40:]))

    return dict(path=out, partition=name, size=size,
                slot=slot or (name[-2:] if name and name.startswith("boot_") else None),
                gpt=gpt, extra=extra)


def sha256_of(path, chunk=1048576):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            b = f.read(chunk)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


# ----------------------------------------------------------------------
# 命令行（可以直接单跑，不受 GUI 影响）
# ----------------------------------------------------------------------
def _cli():
    import argparse
    ap = argparse.ArgumentParser(
        description="EDL 只读分区导出（不需要 root、不需要固件包）")
    sub = ap.add_subparsers(dest="cmd")

    sub.add_parser("env", help="检查 programmer / libusb / 9008 状态")
    sub.add_parser("slot", help="读设备当前运行槽（不需要 root）")
    sub.add_parser("gpt", help="进 9008 读分区表")
    a4 = sub.add_parser("dump", help="读当前槽的 boot 分区")
    a4.add_argument("-o", "--out", default=None, help="输出目录")
    a4.add_argument("--slot", default=None, help="_a / _b 强制指定")
    a4.add_argument("--serial", default=None)
    a4.add_argument("--gpt-timeout", type=int, default=120)
    a4.add_argument("--read-timeout", type=int, default=300)
    a4.add_argument("--no-driver", action="store_true", help="缺驱动时不自动装")
    a5 = sub.add_parser("r", help="读任意分区")
    a5.add_argument("part")
    a5.add_argument("-o", "--out", required=True)
    sub.add_parser("reset", help="退出下载模式")

    a = ap.parse_args()
    try:
        if a.cmd == "env":
            print("programmer:", find_loader() or "未找到")
            print("libusb    :", env_report())
            print("9008 在线 :", _has_edl_device())
            print("驱动状态  :", drivers.summary())
        elif a.cmd == "slot":
            s = slot_suffix()
            if s:
                print("slot_suffix:", s)
            else:
                # 只有一个「读不到」等于没结论。把 adb 侧实况一起打出来：
                # 路径错、端口抢、设备 offline，三种情况的原始返回完全不同。
                print("slot_suffix: 读不到（非 A/B 设备，或 adb 没连）")
                print("  adb     :", android_adb())
                print("  devices :", adb_devices() or "<空>")
                print("  getprop :", adb_run(["shell", "getprop", "ro.boot.slot_suffix"]))
        elif a.cmd == "gpt":
            g = printgpt(find_loader(), log=print)
            for n, v in g.items():
                print("  %-22s off=0x%09X len=0x%09X %s"
                      % (n, v["offset"], v["length"],
                         "ACTIVE" if v["active"] else ""))
        elif a.cmd == "dump":
            d = dump_boot(a.out or os.path.join(os.getcwd(), "edl_dump"),
                          prefer_slot=a.slot, log=print, serial=a.serial,
                          timeout_gpt=a.gpt_timeout,
                          timeout_read=a.read_timeout,
                          allow_driver=not a.no_driver)
            print("\n分区 %s（%d 字节）→ %s"
                  % (d["partition"], d["size"], d["path"]))
            print("sha256", sha256_of(d["path"]))
        elif a.cmd == "r":
            n = read_partition(find_loader(), a.part, a.out, log=print)
            print("读出 %d 字节 → %s" % (n, a.out))
        elif a.cmd == "reset":
            reset(find_loader(), log=print)
        else:
            ap.print_help()
    except EdlError as ex:
        print("[X] %s" % ex)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(_cli())
