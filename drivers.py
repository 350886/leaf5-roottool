# -*- coding: utf-8 -*-
"""
drivers —— 9008 的 WinUSB 驱动：检测 / 引导安装 / 装完复检。

为什么必须有这一步：
    edl 走 libusb，而 libusb 在 Windows 上只能打开**已经绑了 WinUSB /
    libusbK / libusb0 驱动**的设备节点。05C6:9008 在刚进下载模式时，
    Windows 会把它识别成一个「设备」但找不到匹配驱动，problem code = 28
    （CM_PROB_FAILED_INSTALL）。这时候 pyusb 枚举不到它，edl 也就连不上。

    设备本身完全正常 —— 它已经在 9008 里等着了，只是 Windows 没给门。

装驱动的工具用 Zadig（libwdi 的作者 pbatard 写的，同一套东西）。
它内部会生成自签证书、签 inf、装到 TrustedPublisher 再调 SetupAPI，
所以不需要关驱动签名强制，也不需要测试模式。本机已随 edl 工具链带了一份：
    edl-tool/Drivers/Windows/zadig-2.8.exe
构建时拷进 assets，随 EXE 一起分发。

这个模块只做三件事，不做别的：看状态、拉起 Zadig、等它装完。
不写注册表、不自己造 inf、不碰签名策略。
"""

import os
import subprocess
import sys
import time

import usbtrace

QC_VID = 0x05C6
EDL_PID = 0x9008
PROB_NO_DRIVER = 28


def _res_dir():
    """assets 所在目录。打包后是 _MEIPASS，源码模式是脚本所在目录。"""
    base = getattr(sys, "_MEIPASS", None)
    if base:
        return base
    return os.path.dirname(os.path.abspath(__file__))


def find_zadig():
    """
    按优先级找 Zadig：内置 → 环境变量 → 同目录 → edl 工具链原位置。
    返回 (路径, 来源说明) 或 (None, 原因)。
    """
    cands = [
        (os.path.join(_res_dir(), "assets", "zadig.exe"), "内置"),
        (os.path.join(_res_dir(), "assets", "zadig-2.8.exe"), "内置"),
    ]
    env = os.environ.get("LEAF5DUMP_ZADIG")
    if env:
        cands.insert(0, (env, "环境变量"))
    here = os.path.dirname(os.path.abspath(__file__))
    cands += [
        (os.path.join(here, "assets", "zadig.exe"), "同目录"),
        (r"E:\BOOX\edl-tool\Drivers\Windows\zadig-2.8.exe", "edl 工具链"),
        (r"E:\BOOX\edl-tool\Drivers\Windows\zadig.exe", "edl 工具链"),
    ]
    for p, how in cands:
        if p and os.path.isfile(p):
            return p, how
    return None, "未找到 zadig.exe（assets\\zadig.exe）"


def state():
    """
    看 05C6:9008 当前是什么状态。

    erturn dict:
        present     True/False    总线上有没有 9008 节点
        problem     int           CM problem code，0 = 正常
        usable      True/False    pyusb 能不能打开（edl 能不能连）
        desc        节点描述
        inst        实例 ID
    """
    out = {"present": False, "problem": 0, "usable": False,
           "desc": "", "inst": ""}
    for inst, d in usbtrace.enumerate_usb().items():
        if d.get("vid") == QC_VID and d.get("pid") == EDL_PID:
            out["present"] = True
            out["problem"] = d.get("problem", 0)
            out["desc"] = d.get("desc", "")
            out["inst"] = inst
            break
    if out["present"]:
        ok, _ = usbtrace.pyusb_openable()
        out["usable"] = ok
    return out


def summary(st=None):
    """一行结论，给日志用。"""
    st = st or state()
    if not st["present"]:
        return "9008 未接入（设备不在下载模式，或没插）"
    if st["usable"]:
        return "9008 已就绪，可以直接读"
    if st["problem"] == PROB_NO_DRIVER:
        return "9008 已在位但没装驱动（problem 28）—— 需要绑 WinUSB"
    if st["problem"]:
        return "9008 已在位但状态异常（problem %d，%s）" % (
            st["problem"], usbtrace.PROBLEM_TEXT.get(st["problem"], "?"))
    return "9008 已在位但 pyusb 打不开 —— 驱动可能绑成了别的类型"


def _stage(exe):
    """
    把 zadig.exe 解到持久目录再运行。

    和 adb 同一个坑：PyInstaller onefile 的 _MEIPASS 在进程退出时要整个删掉。
    Zadig 是独立进程，用户装完驱动多半不会立刻关窗口 —— 只要它还活着，
    _MEIPASS 里的 zadig.exe 就被占着，删不掉，本程序一直等到超时。
    表现是"活儿干完了窗口关不掉"。

    所以先拷到 %LOCALAPPDATA%\\Leaf5Dump\\bin\\，从那儿启动。
    源码模式不涉及 _MEIPASS，直接用原路径。
    """
    if not getattr(sys, "frozen", False):
        return exe
    try:
        import shutil
        base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
        d = os.path.join(base, "Leaf5Dump", "bin")
        os.makedirs(d, exist_ok=True)
        dst = os.path.join(d, os.path.basename(exe) or "zadig.exe")
        need = (not os.path.isfile(dst) or
                os.path.getsize(dst) != os.path.getsize(exe))
        if need:
            shutil.copy2(exe, dst)
        return dst
    except Exception:
        return exe


def launch_zadig(path=None, log=None):
    """
    以管理员身份拉起 Zadig。装驱动必须提权，不提权 Zadig 自己也会弹 UAC。

    用 ShellExecuteW + "runas"，这样 UAC 弹窗是系统原生的，比自己
    CreateProcess 后被拒绝要清楚得多。

    返回 (ok, msg)。
    """
    p = path or find_zadig()[0]
    if not p:
        return False, "找不到 zadig.exe"
    p = _stage(p)

    def _log(s):
        if log:
            try:
                log(s)
            except Exception:
                pass

    if os.name != "nt":
        return False, "只支持 Windows"

    try:
        import ctypes
        from ctypes import wintypes
        shell32 = ctypes.WinDLL("shell32", use_last_error=True)
        shell32.ShellExecuteW.restype = ctypes.c_void_p
        # 第三个参数 lpFile 是目标程序，第四个是参数
        rc = shell32.ShellExecuteW(None, "runas", p, None,
                                   os.path.dirname(p), 1)
        # ShellExecuteW 返回值 > 32 才算成功
        if not rc or rc <= 32:
            err = ctypes.get_last_error()
            if rc == 5:
                return False, "用户取消了 UAC 提权"
            return False, "启动 Zadig 失败（ShellExecute 返回 %s，错误码 %d）" % (rc, err)
        _log("已拉起 Zadig（管理员）：%s" % p)
        return True, "已拉起 Zadig"
    except Exception as e:
        return False, "启动 Zadig 异常：%s" % e


def wait_ready(seconds=180.0, should_stop=None, on_tick=None):
    """
    等驱动装好。Zadig 是人在操作，所以按秒轮询，直到 05C6:9008 能被 pyusb 打开。

    Zadig 装驱动时设备会短暂消失再出现（驱动重绑定），所以不能一看到消失就判失败，
    只能等"能不能打开"这一个终态。

    返回 (ok, 用时秒, 最后状态)。
    """
    t0 = time.time()
    last = None
    while time.time() - t0 < seconds:
        if should_stop and should_stop():
            return False, time.time() - t0, last
        last = state()
        if last["usable"]:
            return True, time.time() - t0, last
        if on_tick:
            try:
                on_tick(time.time() - t0, last)
            except Exception:
                pass
        time.sleep(1.0)
    return False, time.time() - t0, last or state()


STEPS = [
    "1. Zadig 窗口里点 Options → 勾上 List All Devices（默认只列 USB 设备）",
    "2. 顶部下拉框选 QUSB_BULK（VID 05C6，PID 9008，序列号对得上设备）",
    "3. 右侧驱动框选 WinUSB，点 Replace Driver",
    "4. 看到 The driver was installed successfully 就好了，关掉 Zadig",
    "5. 回到本窗口，点「一键导出」——设备还在下载模式，不用重启",
]


def steps_text():
    return "\n".join(STEPS)


if __name__ == "__main__":
    st = state()
    print("状态：", summary(st))
    print("  存在 %s  problem %s  可用 %s" % (st["present"], st["problem"], st["usable"]))
    if st["inst"]:
        print("  实例 %s" % st["inst"])
    p, how = find_zadig()
    print("zadig：", p or how, ("（%s）" % how) if p else "")
    if st["present"] and not st["usable"]:
        print()
        print(steps_text())
