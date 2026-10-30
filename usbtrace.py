# -*- coding: utf-8 -*-
"""
usbtrace —— 用 SetupAPI 直接枚举 USB 设备节点，判断「设备到底进没进 9008」。

为什么不能用 pyusb 判断：
    pyusb 在 Windows 上走 libusb-1.0 的 winusb 后端，只列得出**已经绑了
    WinUSB/libusb 驱动**的设备。没绑驱动的 9008 在 pyusb 眼里根本不存在。
    于是「设备没进下载模式」和「进了但驱动没装」两种完全相反的情况，
    在 pyusb 看来一模一样 —— 这是 Leaf5Dump v1.0.0 的判定盲区。

    SetupAPI 是 Windows 的枚举器本身，它列的是「总线上实际存在什么」，
    与驱动绑定状态无关。同时用 CM_Get_DevNode_Status 拿 problem code：
        problem == 0  → 驱动正常
        problem == 28 → 驱动未安装（CM_PROB_FAILED_INSTALL）
        problem == 10 → 设备无法启动
    这才是能给出确定结论的数据源。

两者配合：
    SetupAPI 说「有 05C6:9008」+ pyusb 能打开 → 可以直连
    SetupAPI 说「有 05C6:9008」+ pyusb 打不开 → 只差驱动，绑 WinUSB 即可
    SetupAPI 全程没出现 05C6 → 设备压根没进 EDL（OEM 拦了 / 线 / 口）

只读。不写注册表、不装驱动、不动设备。
"""

import ctypes
import os
import re
import sys
import time
from ctypes import wintypes

IS_WIN = (sys.platform == "win32")

# ----------------------------------------------------------------------
# SetupAPI / cfgmgr32 常量
# ----------------------------------------------------------------------
DIGCF_PRESENT = 0x02
DIGCF_ALLCLASSES = 0x04

SPDRP_DEVICEDESC = 0x00          # REG_SZ  设备描述
SPDRP_HARDWAREID = 0x01          # REG_MULTI_SZ  USB\VID_xxxx&PID_yyyy&REV_....
SPDRP_CLASS = 0x07               # REG_SZ  设备类（USB / AndroidUsbDeviceClass ...）
SPDRP_FRIENDLYNAME = 0x0C        # REG_SZ  设备管理器里显示的名字

CM_PROB_FAILED_INSTALL = 28
CM_PROB_NO_DRIVERS = 28
CM_PROB_DISABLED = 22
CM_PROB_FAILED_START = 10

PROBLEM_TEXT = {
    0: "正常",
    1: "未配置",
    3: "驱动损坏",
    10: "设备无法启动",
    12: "资源不足",
    18: "需重装驱动",
    22: "设备被禁用",
    24: "设备不存在",
    28: "驱动未安装",
    31: "无法加载驱动",
    43: "驱动报告设备故障",
}


if IS_WIN:
    class GUID(ctypes.Structure):
        _fields_ = [("Data1", wintypes.DWORD),
                    ("Data2", wintypes.WORD),
                    ("Data3", wintypes.WORD),
                    ("Data4", ctypes.c_ubyte * 8)]

    class SP_DEVINFO_DATA(ctypes.Structure):
        _fields_ = [("cbSize", wintypes.DWORD),
                    ("ClassGuid", GUID),
                    ("DevInst", wintypes.DWORD),
                    ("Reserved", ctypes.POINTER(ctypes.c_ulong))]

    _setupapi = ctypes.WinDLL("setupapi", use_last_error=True)
    _cfgmgr32 = ctypes.WinDLL("cfgmgr32", use_last_error=True)

    _setupapi.SetupDiGetClassDevsW.argtypes = [
        ctypes.c_void_p, wintypes.LPCWSTR, wintypes.HWND, wintypes.DWORD]
    _setupapi.SetupDiGetClassDevsW.restype = ctypes.c_void_p
    _setupapi.SetupDiEnumDeviceInfo.argtypes = [
        ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(SP_DEVINFO_DATA)]
    _setupapi.SetupDiEnumDeviceInfo.restype = wintypes.BOOL
    _setupapi.SetupDiGetDeviceRegistryPropertyW.argtypes = [
        ctypes.c_void_p, ctypes.POINTER(SP_DEVINFO_DATA), wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p, wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD)]
    _setupapi.SetupDiGetDeviceRegistryPropertyW.restype = wintypes.BOOL
    _setupapi.SetupDiDestroyDeviceInfoList.argtypes = [ctypes.c_void_p]
    _setupapi.SetupDiDestroyDeviceInfoList.restype = wintypes.BOOL

    _cfgmgr32.CM_Get_DevNode_Status.argtypes = [
        ctypes.POINTER(wintypes.ULONG), ctypes.POINTER(wintypes.ULONG),
        wintypes.DWORD, wintypes.ULONG]
    _cfgmgr32.CM_Get_DevNode_Status.restype = ctypes.c_long


def _prop(hdev, did, prop):
    """读一条 SPDRP_* 注册表属性。REG_MULTI_SZ 拼成单条字符串。"""
    buf = ctypes.create_unicode_buffer(2048)
    typ = wintypes.DWORD()
    need = wintypes.DWORD()
    ok = _setupapi.SetupDiGetDeviceRegistryPropertyW(
        hdev, ctypes.byref(did), prop, ctypes.byref(typ),
        buf, ctypes.sizeof(buf), ctypes.byref(need))
    if not ok:
        return ""
    s = buf.value
    # REG_MULTI_SZ 读出来是 "a\0b\0"，create_unicode_buffer 只到第一个 \0，
    # 但 SetupAPI 会把多串拼进同一缓冲区，raw 里仍有后续内容。
    if typ.value == 7:      # REG_MULTI_SZ
        raw = ctypes.string_at(buf, min(need.value, ctypes.sizeof(buf)))
        parts = [p.decode("utf-16-le", "replace")
                 for p in raw.split(b"\x00\x00")]
        s = " ".join(x for x in parts if x.strip())
    return s


def _problem(devinst):
    """CM_Get_DevNode_Status → (status, problem)。失败返回 (0, -1)。"""
    status = wintypes.ULONG()
    problem = wintypes.ULONG()
    rc = _cfgmgr32.CM_Get_DevNode_Status(
        ctypes.byref(status), ctypes.byref(problem), devinst, 0)
    if rc != 0:
        return 0, -1
    return status.value, problem.value


_VID_RE = re.compile(r"VID_([0-9A-F]{4})", re.I)
_PID_RE = re.compile(r"PID_([0-9A-F]{4})", re.I)

QC_VID = 0x05C6
EDL_PIDS = {
    0x9008: "9008 EDL",
    0x900E: "900E EDL",
    0x901D: "901D diag",
    0x9025: "9025 EDL",
}
ADB_VIDS = {0x18D1, 0x2A70, 0x2207, 0x0E8D, 0x2717, 0x04E8}


def enumerate_usb():
    """
    返回 dict: 实例ID -> {vid, pid, desc, cls, problem, problem_text}

    实例ID 是形如 "USB\\VID_05C6&PID_9008\\6&1A2B3C4D&0&2" 的稳定字符串，
    同一台设备反复插拔实例ID不变，所以可以直接拿来做 diff。
    """
    out = {}
    if not IS_WIN:
        return out

    # enumerator 传 "USB" 只列 USB 总线，比 ALLCLASSES 快一个数量级，
    # 但会漏掉部分安卓复合设备（走 AndroidUsbDeviceClass），所以先试 USB，
    # 若结果为空再退回 ALLCLASSES。
    for enum, flags in (("USB", DIGCF_PRESENT), (None, DIGCF_PRESENT | DIGCF_ALLCLASSES)):
        hdev = _setupapi.SetupDiGetClassDevsW(
            None, enum, None, flags)
        if not hdev or hdev == ctypes.c_void_p(-1).value:
            continue
        try:
            i = 0
            while True:
                did = SP_DEVINFO_DATA()
                did.cbSize = ctypes.sizeof(SP_DEVINFO_DATA)
                if not _setupapi.SetupDiEnumDeviceInfo(hdev, i, ctypes.byref(did)):
                    break
                i += 1
                hwid = _prop(hdev, did, SPDRP_HARDWAREID)
                if not hwid or "USB\\" not in hwid.upper():
                    continue
                mv = _VID_RE.search(hwid)
                mp = _PID_RE.search(hwid)
                if not (mv and mp):
                    continue
                vid = int(mv.group(1), 16)
                pid = int(mp.group(1), 16)
                # 只要高通或安卓相关的，别把键盘鼠标罗列进来
                if vid not in ADB_VIDS and vid != QC_VID:
                    continue
                st, pb = _problem(did.DevInst)
                inst = hwid.split()[0]
                desc = _prop(hdev, did, SPDRP_FRIENDLYNAME) or _prop(hdev, did, SPDRP_DEVICEDESC)
                out[inst] = {
                    "vid": vid, "pid": pid,
                    "desc": desc or "?",
                    "cls": _prop(hdev, did, SPDRP_CLASS) or "?",
                    "problem": pb,
                    "problem_text": PROBLEM_TEXT.get(pb, "代码 %d" % pb) if pb else "正常",
                }
        finally:
            _setupapi.SetupDiDestroyDeviceInfoList(hdev)
        if out:
            break
    return out


def summarize(snap):
    """一行摘要，给人看的。"""
    if not snap:
        return "无高通/安卓 USB 节点"
    parts = []
    for inst, d in snap.items():
        tag = EDL_PIDS.get(d["pid"]) if d["vid"] == QC_VID else "adb/mtp"
        if not tag:
            tag = "%04X:%04X" % (d["vid"], d["pid"])
        bad = "" if d["problem"] == 0 else " [%s]" % d["problem_text"]
        parts.append("%s%s" % (tag, bad))
    return " | ".join(parts)


def _ensure_libusb():
    """
    单独跑这个文件时没有 edlcore 帮忙注入 DLL 路径，pyusb 会报
    "No backend available"。这里补一次，幂等。
    """
    try:
        import libusb_package
    except Exception:
        return
    try:
        import os
        p = libusb_package.find_library("libusb-1.0")
        if p:
            d = os.path.dirname(p)
            try:
                os.add_dll_directory(d)
            except Exception:
                pass
            if d not in os.environ.get("PATH", ""):
                os.environ["PATH"] = d + os.pathsep + os.environ.get("PATH", "")
    except Exception:
        pass


def pyusb_openable():
    """pyusb 能真正打开的设备 —— 这才是 edl 能不能连的前提。"""
    _ensure_libusb()
    try:
        import usb.core  # noqa
    except Exception:
        return False, "pyusb 不可用"
    try:
        for d in usb.core.find(find_all=True, idVendor=QC_VID):
            if d.idProduct in EDL_PIDS:
                return True, EDL_PIDS[d.idProduct]
    except Exception as e:
        return False, "pyusb 枚举失败 %s" % e
    return False, "pyusb 看不到 05C6"


def adb_state(adb_path=None, port=None):
    """
    不带 adb 时用 SetupAPI 看有没有安卓设备节点；带 adb 时问 adb。

    port 必须跟着主流程走：adb 认 ANDROID_ADB_SERVER_PORT 环境变量，
    这里不传的话 `adb devices` 会自己在 5037 另起一个 daemon。
    两个 daemon 会抢同一个 USB 句柄 —— 谁先抢到谁看得到设备，
    另一个就永远显示空列表（Leaf5RootTool v1.1.0 新机器上踩到的坑）。
    """
    if adb_path:
        try:
            import subprocess
            env = dict(os.environ)
            if port:
                env["ANDROID_ADB_SERVER_PORT"] = str(port)
            env.pop("ADB_SERVER_SOCKET", None)
            r = subprocess.run([adb_path, "devices"], capture_output=True,
                               text=True, timeout=8, env=env,
                               creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            lines = [x for x in r.stdout.splitlines()[1:] if x.strip()]
            return lines
        except Exception:
            return []
    return [i for i, d in enumerate_usb().items()
            if d["vid"] in ADB_VIDS and d["problem"] == 0]


def adb_diag(port=None):
    """
    `adb devices` 返回空时，回答「到底卡在哪一环」。

    返回 (kind, msg, hint)。kind 用于分支，msg 直接进日志。

      no_usb        总线上没有任何安卓/高通节点 → 线 / 口 / 没开机
      adb_nodriver  有 ADB 接口节点但 problem != 0 → Windows 侧缺驱动
      in_edl        在 9008/900E → 设备不在正常系统里
      qc_other      高通其它 PID（diag / 9006 等）
      adb_ok        节点正常但 adb 看不到 → 调试开关 / 授权 / 端口
    """
    snap = enumerate_usb()
    if not snap:
        return ("no_usb",
                "USB 总线上没有任何安卓/高通设备 —— 设备没被枚举到",
                "查数据线是不是只有充电功能、换一个 USB 口（直连后置口，别用前置/集线器）、"
                "确认设备已开机并解锁屏幕")

    adb_nodes, edl_nodes, other = [], [], []
    for inst, d in snap.items():
        if d["vid"] == QC_VID and d["pid"] in EDL_PIDS:
            edl_nodes.append((inst, d))
        elif d["vid"] in ADB_VIDS:
            adb_nodes.append((inst, d))
        else:
            other.append((inst, d))

    if adb_nodes:
        bad = [x for x in adb_nodes if x[1]["problem"] != 0]
        if bad:
            d = bad[0][1]
            return ("adb_nodriver",
                    "安卓 ADB 接口在，但 Windows 侧驱动没装好：%s（problem %d · %s）"
                    % (d["desc"], d["problem"], d["problem_text"]),
                    "设备管理器里会给它一个黄色感叹号。装 Google USB Driver"
                    "（android_winusb.inf，选「Android ADB Interface」），"
                    "或用 Zadig 把这一项也换成 WinUSB")
        return ("adb_ok",
                "ADB 接口节点正常（%s），但 adb 列不出设备" % adb_nodes[0][1]["desc"],
                "多半是设备上「USB 调试」没开或没点授权弹窗；"
                "也可能是别的 adb 进程/端口在抢（先关掉 Android Studio、手机助手之类）")

    if edl_nodes:
        return ("in_edl",
                "设备当前在下载模式：%s" % EDL_PIDS.get(edl_nodes[0][1]["pid"], "EDL"),
                "长按电源键 10 秒退出下载模式，正常开机后再点「刷新设备」")

    d = other[0][1]
    return ("qc_other",
            "只看到高通/安卓设备的其它端口：%04X:%04X %s"
            % (d["vid"], d["pid"], d["desc"]),
            "设备可能在 diag/9006 之类的中间态，断电重启一次")


# ----------------------------------------------------------------------
# 带时间轴的追踪
# ----------------------------------------------------------------------
class Trace:
    """
    每 step 秒采样一次 USB 拓扑，记录新增/消失，跑完后给出判定。

    用法：
        t = Trace(step=0.5)
        t.start()                 # 记一次基线
        trigger()                 # 这里发 adb reboot edl
        t.run(30)                 # 阻塞采样 30 秒
        print(t.report())
    """

    def __init__(self, step=0.5, on_tick=None):
        self.step = step
        self.on_tick = on_tick          # 回调 (elapsed, snap, events)
        self.base = {}
        self.snap = {}
        self.events = []                # [(t, kind, inst, detail)]
        self.t0 = 0.0
        self._seen = set()
        self._gone = set()

    def start(self):
        self.base = enumerate_usb()
        self.snap = dict(self.base)
        self.t0 = time.time()
        self._seen = set(self.base)
        for inst in self.base:
            self.events.append((0.0, "base", inst, self.base[inst]))
        return self.base

    def poll(self):
        now = enumerate_usb()
        t = time.time() - self.t0
        for inst, d in now.items():
            if inst not in self._seen:
                self._seen.add(inst)
                self.events.append((t, "add", inst, d))
        for inst in list(self._seen):
            if inst not in now:
                self._seen.discard(inst)
                self._gone.add(inst)
                self.events.append((t, "del", inst, self.base.get(inst) or {}))
        self.snap = now
        return now

    def run(self, seconds, should_stop=None):
        end = time.time() + seconds
        err_shown = False
        while time.time() < end:
            if should_stop and should_stop():
                break
            now = self.poll()
            if self.on_tick:
                try:
                    self.on_tick(time.time() - self.t0, now, self.events)
                except Exception as e:
                    # 静默吞掉回调异常会让"界面不动"变成一个查不出原因的谜。
                    # 只报一次，不刷屏。
                    if not err_shown:
                        err_shown = True
                        try:
                            sys.stderr.write("[usbtrace] on_tick 异常: %r\n" % (e,))
                        except Exception:
                            pass
            time.sleep(self.step)
        return self.report()

    # ------------------------------------------------------------------
    def qc_nodes(self):
        """本次追踪里出现过的所有高通节点（含已消失的）。"""
        out = []
        for t, kind, inst, d in self.events:
            if d.get("vid") == QC_VID:
                out.append((t, kind, inst, d))
        return out

    def edl_nodes(self):
        return [x for x in self.qc_nodes() if x[3].get("pid") in EDL_PIDS]

    def verdict(self):
        """
        返回 (code, 一句话结论, 下一步动作)。

        code:
            ok_ready      9008 在，pyusb 能打开            → 直接读
            ok_nodriver   9008 在，驱动没绑                → 绑 WinUSB
            no_edl        设备从没进过真正的高通下载模式    → 换入口方式
            no_device     设备完全不在（线/口/关机）        → 检查物理连接
            other_qc      进了别的模式（diag 等）          → 换个入口
        """
        edl = self.edl_nodes()
        qc = self.qc_nodes()

        if edl:
            ok, why = pyusb_openable()
            if ok:
                return ("ok_ready",
                        "9008 在线且可被 pyusb 打开（%s）" % why,
                        "不需要任何操作")
            probs = [x[3].get("problem", 0) for x in edl]
            if any(p and p != 0 for p in probs):
                txt = PROBLEM_TEXT.get(max(probs), "代码 %d" % max(probs))
                return ("ok_nodriver",
                        "设备已经在 9008，但 Windows 侧没装驱动（%s）" % txt,
                        "用 Zadig 把 05C6:9008 换成 WinUSB —— 设备已经在下载模式，"
                        "这一步做完直接重跑导出，不用再重启设备")
            return ("ok_nodriver",
                    "设备已经在 9008，但 pyusb 打不开（%s）" % why,
                    "用 Zadig 把 05C6:9008 换成 WinUSB")

        if qc:
            pids = sorted({d.get("pid") for _, _, _, d in qc})
            return ("other_qc",
                    "设备进了高通模式但不是 9008（PID %s）"
                    % ", ".join("0x%04X %s" % (p, EDL_PIDS.get(p, "?")) for p in pids),
                    "用 EDL 组合键重进：关机 → 按住音量上+下 → 插 USB")

        if self.snap:
            return ("no_edl",
                    "设备还在（%s），但没有进入下载模式 —— reboot edl 没生效"
                    % summarize(self.snap),
                    "OEM 拦了 adb 侧入口。改用硬件组合键：关机 → 按住音量上（或上+下）→ 插 USB")

        return ("no_device",
                "追踪期间总线上没有任何高通/安卓设备节点",
                "设备没连上或已断电：换线、换 USB 口（别用前置/HUB）、确认已开机或已在下载模式")

    def report(self):
        code, msg, act = self.verdict()
        lines = []
        lines.append("USB 时间轴：")
        if not self.events:
            lines.append("  （空）")
        for t, kind, inst, d in self.events:
            if kind == "base":
                if d.get("vid") == QC_VID or d.get("pid") in EDL_PIDS:
                    lines.append("  %5.2fs  基线存在  %s  %s"
                                 % (t, inst.split("\\")[1] if "\\" in inst else inst,
                                    d.get("desc", "")))
                continue
            short = inst.split("\\")[1] if "\\" in inst else inst
            if kind == "add":
                lines.append("  %5.2fs  + 出现    %s  %s  [%s]"
                             % (t, short, d.get("desc", ""), d.get("problem_text", "")))
            else:
                lines.append("  %5.2fs  - 消失    %s" % (t, short))
        lines.append("")
        lines.append("判定：" + msg)
        lines.append("下一步：" + act)
        return "\n".join(lines)


def report_once():
    """
    不追踪，只报当前状态 + 结论。给 `Leaf5Dump --trace`（不带秒数）用。
    适合"现在到底什么情况"这种即时问答。
    """
    snap = enumerate_usb()
    t = Trace()
    t.base = snap
    t.snap = snap
    t._seen = set(snap)
    code, msg, act = t.verdict()
    lines = ["当前 USB 节点："]
    if not snap:
        lines.append("  （无高通/安卓设备）")
    for inst, d in snap.items():
        lines.append("  %-46s %04X:%04X  %s  [%s]"
                     % (inst, d["vid"], d["pid"], d["desc"], d["problem_text"]))
    ok, why = pyusb_openable()
    lines.append("pyusb：%s" % ("可打开 " + str(why) if ok else why))
    lines.append("")
    lines.append("判定：" + msg)
    lines.append("下一步：" + act)
    return "\n".join(lines)


# ----------------------------------------------------------------------
# 单独跑：python usbtrace.py [秒数] [--reboot]
# ----------------------------------------------------------------------
def main(argv):
    secs = 20.0
    for a in argv:
        if re.match(r"^\d+(\.\d+)?$", a):
            secs = float(a)
    do_reboot = "--reboot" in argv

    print("基线：")
    base = enumerate_usb()
    if not base:
        print("  无高通/安卓 USB 节点（设备没插，或插的是纯充电线）")
    for inst, d in base.items():
        print("  %-46s %04X:%04X  %s  [%s]"
              % (inst, d["vid"], d["pid"], d["desc"], d["problem_text"]))
    print("  pyusb: %s" % (pyusb_openable(),))

    t = Trace(step=0.5)
    t.start()

    if do_reboot:
        adbp = None
        try:
            import usbwatch
            adbp = usbwatch.find_adb()
        except Exception:
            pass
        if adbp:
            import subprocess
            print("\n发送 adb reboot edl ...")
            try:
                r = subprocess.run([adbp, "reboot", "edl"], capture_output=True,
                                   text=True, timeout=12,
                                   creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
                if r.returncode != 0:
                    tail = (r.stderr or r.stdout or "").strip().splitlines()
                    print("  失败（rc=%d）：%s"
                          % (r.returncode, tail[-1] if tail else "无输出"))
                    print("  常见：adb 看不到设备时 reboot 无效，需要先让设备在 adb 里可见")
            except Exception as e:
                print("  异常：%s" % e)
        else:
            print("\n找不到 adb，只做被动追踪")

    print("\n追踪 %.0f 秒（每 0.5s 采样）..." % secs)

    def tick(el, snap, evs):
        for t_, kind, inst, d in evs:
            if kind != "base" and abs(t_ - el) < 0.6:
                short = inst.split("\\")[1] if "\\" in inst else inst
                print("  %5.1fs %s %s" % (t_, "+" if kind == "add" else "-", short))

    t.run(secs, should_stop=lambda: False)
    print()
    print(t.report())
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
