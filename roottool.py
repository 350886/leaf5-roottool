#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Leaf5 Root Tool — 集成 adb 的一键 root 客户端

内嵌 adb.exe，不依赖系统里装没装 platform-tools。
流程与 scripts/root_try.sh 完全一致，只是把 shell 换成 Python。

  检测设备 -> 部署载荷 -> 最多 N 轮 (必要时重启等就绪) -> 判定 -> 保留 su

命令行：
  roottool.exe                图形界面
  roottool.exe --check        只检测，不动设备（冒烟测试用）
  roottool.exe --root 3       无界面跑 3 轮
  roottool.exe --port 5053    指定 adb server 端口
"""

import os
import re
import sys
import struct
import time
import queue
import shutil
import hashlib
import tempfile
import argparse
import subprocess
import threading

# Google Play 模块单独一个文件，不参与 root 流程。
# 它的 adb 由 App 注入（同一个 Adb 实例），所以不需要自己找 adb.exe。
try:
    import gp as gplay
except ImportError:
    gplay = None

# tkinter 只在 GUI 模式需要；CLI 模式（--check / --root）在没有 tk 的环境也能跑
try:
    import tkinter as tk
    from tkinter import ttk
    from tkinter import messagebox
except ImportError:  # 精简版 Python 可能没带 tcl/tk
    tk = None
    ttk = None
    messagebox = None

# ----------------------------------------------------------------------------
# 常量：设备端布局与已验证的 chain 配置
# 改动前先读 leaf5-ghostlock/docs/ROOT_CHAIN.md，每个变量都对应一条死路
# ----------------------------------------------------------------------------

APP_NAME = "Leaf5 Root Tool"
APP_VER = "1.1.4"

# 本工具适配的唯一目标。写在界面上、写进日志、拿来卡住别的机型。
# 62 个偏移 + services.jar 补丁点全部绑死在这个三元组上，换任何一个都不成立。
TARGET_MODEL = "Leaf5"
TARGET_FIRMWARE = "4.2.3-rel_0928"
TARGET_KERNEL = "4.19.157"

DEV_ROOT = "/data/local/tmp"
DEV_BIN = f"{DEV_ROOT}/exploit/aarch64"
DEV_RUNS = f"{DEV_ROOT}/runs"
DEV_SU = f"{DEV_ROOT}/su"
DEV_PROBE = f"{DEV_ROOT}/exec_probe.txt"

# reboot 后 uptime < 90s 就起跑，三轮全部崩在 round 1 刚起步（T1519/T1522/T1524）
MIN_UP = 90
# 每轮从起跑到收工的上限。实测 96 秒收工，失败约 210 秒
ROUND_LIMIT = 210
# 单轮 exploit 的 timeout(1) 参数
RUN_TIMEOUT = 150
SLEEP_SEC = 480

# B405 / B407 / B410 三次实测通过的组合
CHAIN_ENV = (
    "SKIP_LEAK=1 PERF_CRED=1 PERF_TASK=1 "
    "WRITE_PLAN=selinux,prmptr,bsetptr THREAD_RACE=1 ROUTE_ROUNDS=3 "
    "STACK_LOCK=1 PARENT_PAINT=1 CAPS_FULL_FINISH=1 FAST_ROOT=1 INPROC_SU=1 "
    "PSELECT_ROUTE_ATTEMPTS=2 PAGE_SETUP_ATTEMPTS=1 MM_SPRAY_SLABS=0"
)

# 本机 adb server 用独立端口，避免跟 Android Studio / 别的工具抢 5037
DEFAULT_PORT = 5053

# ---- Magisk 集成 ----------------------------------------------------------
MAGISK_VER = "31.1"
DEV_MGK = f"{DEV_ROOT}/mgk"
DEV_KITS = f"{DEV_MGK}/kits"

# APK 里的库名 -> 设备上的可执行名。Magisk 把每个二进制都伪装成 .so 塞在 lib/ 下
APK_TOOLS = {
    "lib/arm64-v8a/libmagiskboot.so": "magiskboot",
    "lib/arm64-v8a/libmagiskinit.so": "magiskinit",
    "lib/arm64-v8a/libmagisk.so": "magisk64",
    "lib/armeabi-v7a/libmagisk.so": "magisk32",
    "lib/arm64-v8a/libmagiskpolicy.so": "magiskpolicy",
    "lib/arm64-v8a/libinit-ld.so": "init-ld",
    "lib/arm64-v8a/libbusybox.so": "busybox",
    "assets/boot_patch.sh": "boot_patch.sh",
    "assets/util_functions.sh": "util_functions.sh",
}

# /data/adb/magisk 里必须有 busybox，否则 setup_magisk_env 直接 abort，
# post-fs-data 提前返回，模块永远不挂载（bootstages.rs:73-115）
MAGISK_RUNTIME = ("busybox", "magiskboot", "magiskinit", "magisk32", "magisk64",
                  "magiskpolicy", "init-ld", "boot_patch.sh", "util_functions.sh")

# ---- AMS 修复模块 --------------------------------------------------------
MOD_ID = "boox-ams-fix"
MOD_DIR = f"/data/adb/modules/{MOD_ID}"
# services.jar 里 classes.dex 的补丁点，偏移按固件 4.2.3-rel_0928 现算
DEX_OFF = 0x2B2FEE
DEX_OLD = bytes([0x38, 0x01, 0x33, 0x00])   # if-eqz v1, +0x33（文石 WebView 追踪）
DEX_NEW = bytes([0x38, 0x01, 0x3F, 0x00])   # if-eqz v1, +0x3F（return-void）

MOD_PROP = """id={id}
name=Boox AMS NPE Fix (Leaf5 4.2.3)
version=v1.0-leaf5-4.2.3
versionCode=1
author=leaf5-roottool
description=修 ONYX services.jar 里 ActivityManagerService.addPackageDependency 对 null ProcessRecord 的解引用。不修的话 Magisk App 会卡在启动画面（root 本身正常）。单字节补丁 classes.dex 0x{off:x}: {old} -> {new}。
""".format(id=MOD_ID, off=DEX_OFF, old=DEX_OLD.hex(" "), new=DEX_NEW.hex(" "))

CREATE_NO_WINDOW = 0x08000000 if os.name == "nt" else 0


def resource_path(*parts):
    """onefile 解包目录 / 源码目录"""
    base = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base, *parts)


def _gp_ui_enabled():
    """
    本 EXE 是否集成了 Google Play —— 编译期定的，不在运行期猜。

    带版打包时 build.py 往包里塞一个空标记 assets/gp_ui.on；普通版没有这个
    标记，界面上就不出现那一行（按钮 + 状态标签），窗口也少 28px。
    源码直接跑（没 frozen）一律当集成版处理，开发时免得看不见按钮。
    """
    if not getattr(sys, "frozen", False):
        return True
    return os.path.isfile(resource_path("assets", "gp_ui.on"))


GP_ENABLED = _gp_ui_enabled()


def app_data_dir():
    base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
    return os.path.join(base, "Leaf5RootTool")


def md5_of(path):
    h = hashlib.md5()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def boot_hdr(path):
    """
    解析 Android boot image 头（v0~v2）。只要三个值：
      kernel_size(0x08) / ramdisk_size(0x10) / header_version(0x28)

    Magisk patch 的正确形态是：kernel 一个字节不动，ramdisk 涨几十 KB
    （塞进 magiskinit 那份压缩包）。kernel_size 变了说明补丁动的不是该动的地方，
    或者输入拿错了分区 —— 这时候写进去就是砖，必须在 dd 之前拦住。
    """
    try:
        with open(path, "rb") as f:
            d = f.read(64)
    except OSError:
        return None
    if len(d) < 48 or d[:8] != b"ANDROID!":
        return None
    return {
        "kernel": struct.unpack("<I", d[8:12])[0],
        "ramdisk": struct.unpack("<I", d[16:20])[0],
        "hdr_ver": struct.unpack("<I", d[40:44])[0],
        "size": os.path.getsize(path),
    }


def backup_dir():
    """PC 侧留档目录：%LOCALAPPDATA%\\Leaf5RootTool\\backup\\"""
    d = os.path.join(app_data_dir(), "backup")
    os.makedirs(d, exist_ok=True)
    return d


# ----------------------------------------------------------------------------
# Magisk 工具提取 + DEX 补丁
# ----------------------------------------------------------------------------

def magisk_apk_path():
    """内嵌的 Magisk APK；也允许放一个同名文件到 EXE 旁边覆盖"""
    ext = os.path.join(os.path.dirname(os.path.abspath(sys.argv[0])),
                       f"Magisk-v{MAGISK_VER}.apk")
    if os.path.isfile(ext):
        return ext
    return resource_path("assets", "magisk", f"Magisk-v{MAGISK_VER}.apk")


def extract_apk_tools(apk, dest):
    """
    从 APK 里取出 magiskboot / magiskinit / magisk64 ... 落到 dest。

    为什么不在 PC 上跑 boot_patch.sh：magiskboot 是 aarch64 的 ELF，
    Windows 上根本执行不了。只能在设备上解包、修补、再打包。
    """
    import zipfile
    os.makedirs(dest, exist_ok=True)
    out = {}
    with zipfile.ZipFile(apk) as z:
        names = set(z.namelist())
        for arc, dst in APK_TOOLS.items():
            if arc not in names:
                raise AdbError(f"APK 里没有 {arc}（版本不对？）")
            p = os.path.join(dest, dst)
            with z.open(arc) as src, open(p, "wb") as f:
                shutil.copyfileobj(src, f)
            out[dst] = p
    return out


def patch_services_jar(src, dst, log=None):
    """
    把 ONYX services.jar 里 classes.dex 的 null 分支改回 return-void。

    AOSP 原版：proc == null 就直接 return；
    文石 4.2.3 把这个分支改成跳去自己的 WebView 使用追踪代码，
    一进去就 iget-object v0, v1, ProcessRecord;->info，v1 为 null ⇒ NPE。
    Magisk 的 root 守护进程由 app_process 起、不在 PidMap 里 ⇒ proc 恒 null
    ⇒ Magisk App 每次都在启动画面崩掉。

    单字节改动之后必须重算 DEX 头的两个校验，否则 ART 拒绝加载。
    """
    import zipfile
    import zlib
    import struct

    log = log or (lambda s: None)
    with zipfile.ZipFile(src) as zin:
        if "classes.dex" not in zin.namelist():
            raise AdbError("services.jar 里没有 classes.dex")
        raw = zin.read("classes.dex")
        if len(raw) <= DEX_OFF + 4:
            raise AdbError("classes.dex 比补丁点还短，固件不对")
        if raw[:4] != b"dex\n":
            raise AdbError("classes.dex 魔数不对")

        cur = raw[DEX_OFF:DEX_OFF + 4]
        if cur == DEX_NEW:
            log("  [=] services.jar 已经是修补后的状态，跳过")
            shutil.copyfile(src, dst)
            return dst, False
        if cur != DEX_OLD:
            raise AdbError(
                f"0x{DEX_OFF:x} 处不是预期字节（读到 {cur.hex()}，期望 {DEX_OLD.hex()}）。"
                f"这个偏移只对固件 4.2.3-rel_0928 成立，换版本必须重算。")

        buf = bytearray(raw)
        buf[DEX_OFF:DEX_OFF + 4] = DEX_NEW
        # signature = SHA-1 over [32:]
        buf[0x0C:0x20] = hashlib.sha1(bytes(buf[32:])).digest()
        # checksum = Adler32 over [12:]
        buf[0x08:0x0C] = struct.pack("<I", zlib.adler32(bytes(buf[12:])) & 0xFFFFFFFF)
        log(f"  补丁 classes.dex 0x{DEX_OFF:x}: {DEX_OLD.hex()} -> {DEX_NEW.hex()}")
        log(f"    signature={buf[0x0C:0x20].hex()[:16]}…  "
            f"checksum=0x{struct.unpack('<I', buf[0x08:0x0C])[0]:08x}")

        with zipfile.ZipFile(dst, "w") as zout:
            for item in zin.infolist():
                data = bytes(buf) if item.filename == "classes.dex" else zin.read(item.filename)
                zi = zipfile.ZipInfo(item.filename, date_time=item.date_time)
                zi.compress_type = item.compress_type
                zi.external_attr = item.external_attr
                zout.writestr(zi, data)
    return dst, True


# ----------------------------------------------------------------------------
# adb 安装与封装
# ----------------------------------------------------------------------------

class AdbError(Exception):
    pass


def install_adb(port=DEFAULT_PORT):
    """
    把内嵌的 adb 三件套铺到 %LOCALAPPDATA%\\Leaf5RootTool\\bin。

    不直接从 onefile 的解包目录跑：那个目录在 EXE 退出时会被删掉，
    而 adb server 是独立进程，正跑着的那份 adb.exe 被删会留下僵尸 server。
    """
    bindir = os.path.join(app_data_dir(), "bin")
    os.makedirs(bindir, exist_ok=True)

    for name in ("adb.exe", "AdbWinApi.dll", "AdbWinUsbApi.dll"):
        src = resource_path("assets", "adb", name)
        dst = os.path.join(bindir, name)
        if not os.path.isfile(src):
            raise AdbError(f"包内缺 {name}，EXE 装配不完整")
        need = True
        if os.path.isfile(dst):
            try:
                need = os.path.getsize(src) != os.path.getsize(dst) or \
                       md5_of(src) != md5_of(dst)
            except OSError:
                need = True
        if need:
            tmp = dst + ".tmp"
            shutil.copy2(src, tmp)
            try:
                os.replace(tmp, dst)
            except OSError:
                # adb server 正占着这个文件时替换会失败，用现有那份就行
                try:
                    os.remove(tmp)
                except OSError:
                    pass
    return os.path.join(bindir, "adb.exe")


class Adb:
    def __init__(self, exe, port=DEFAULT_PORT, serial=None, logger=None):
        self.exe = exe
        self.port = int(port)
        self.serial = serial
        self._log = logger or (lambda s: None)
        self.env = dict(os.environ)
        self.env["ANDROID_ADB_SERVER_PORT"] = str(self.port)
        # 让 adb 不要因为 HOME 里的 .android 配置去连别的 server
        self.env.pop("ADB_SERVER_SOCKET", None)

    # -- 底层 ----------------------------------------------------------------

    def _argv(self, args, serial=True):
        cmd = [self.exe]
        if serial and self.serial:
            cmd += ["-s", self.serial]
        cmd += list(args)
        return cmd

    def run(self, args, timeout=20, serial=True):
        try:
            p = subprocess.run(
                self._argv(args, serial),
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=timeout, env=self.env, creationflags=CREATE_NO_WINDOW,
            )
            out = p.stdout.decode("utf-8", "replace").replace("\r\n", "\n")
            err = p.stderr.decode("utf-8", "replace").replace("\r\n", "\n")
            return p.returncode, out, err
        except subprocess.TimeoutExpired:
            return 124, "", "timeout"
        except FileNotFoundError:
            return 127, "", f"找不到 {self.exe}"

    def shell(self, cmd, timeout=20):
        rc, out, err = self.run(["shell", cmd], timeout=timeout)
        return out.strip()

    def spawn_background(self, cmd):
        """
        在设备上起一个脱离 adb 会话的进程。

        `adb shell "cmd &"` 会因为 shell 退出把子进程带走；
        这里让远端 shell 立刻返回，子进程用 setsid 脱离会话。
        """
        wrapped = f"( {cmd} ) >/dev/null 2>&1 &"
        rc, out, err = self.run(["shell", wrapped], timeout=15)
        return rc, out, err

    def push(self, local, remote, timeout=180):
        rc, out, err = self.run(["push", local, remote], timeout=timeout)
        if rc != 0:
            raise AdbError(f"push 失败 {os.path.basename(local)}: {(err or out).strip()[:200]}")
        return out

    def pull(self, remote, local, timeout=600):
        """
        拉文件到 PC。目标目录不存在时先建。

        备份 boot 这一步不能省 —— 只在设备上留一份的话，boot 写坏后系统起不来，
        /data 也读不到，那份备份等于不存在。
        """
        d = os.path.dirname(local)
        if d:
            os.makedirs(d, exist_ok=True)
        rc, out, err = self.run(["pull", remote, local], timeout=timeout)
        if rc != 0:
            raise AdbError(f"pull 失败 {os.path.basename(remote)}: {(err or out).strip()[:200]}")
        if not os.path.isfile(local):
            raise AdbError(f"pull 返回成功但文件不在：{local}")
        return out

    # -- 上层 ----------------------------------------------------------------

    def start_server(self):
        rc, out, err = self.run(["start-server"], timeout=40, serial=False)
        if rc != 0:
            raise AdbError(f"adb start-server 失败: {(err or out).strip()[:200]}")

    def kill_server(self):
        try:
            self.run(["kill-server"], timeout=15, serial=False)
        except Exception:
            pass

    def devices(self):
        rc, out, err = self.run(["devices", "-l"], timeout=20, serial=False)
        if rc != 0:
            raise AdbError(f"adb devices 失败: {(err or out).strip()[:200]}")
        result = []
        for line in out.splitlines()[1:]:
            line = line.strip()
            if not line:
                continue
            parts = line.split()
            if len(parts) < 2:
                continue
            sn, state = parts[0], parts[1]
            extra = {}
            for tok in parts[2:]:
                if ":" in tok:
                    k, v = tok.split(":", 1)
                    extra[k] = v
            result.append({"serial": sn, "state": state, "model": extra.get("model", ""),
                           "device": extra.get("device", ""), "product": extra.get("product", "")})
        return result

    # 便捷读值
    def getprop(self, key):
        return self.shell(f"getprop {key}", timeout=10)

    def uptime(self):
        v = self.shell("cut -d. -f1 /proc/uptime", timeout=8)
        try:
            return int(v.strip())
        except (ValueError, AttributeError):
            return None

    def sysname(self):
        return self.shell("uname -s", timeout=8)

    def getenforce(self):
        return self.shell("getenforce", timeout=8)


# ----------------------------------------------------------------------------
# 流程
# ----------------------------------------------------------------------------

class StopRequested(Exception):
    pass


class ModelMismatch(Exception):
    """
    机型/内核不是本工具适配的那一版。

    单独一个类型而不是 AdbError：adbd 好着呢，adbp 命令也都通，
    问题在"这台机器不该被 root"。上层要能把"接线问题"和"机型不对"
    分开处理 —— 前者重插线，后者只能换机器或者显式放行。
    """
    pass


class AlreadyRooted(Exception):
    """
    设备上已经有可用的 su，没有必要再跑一遍。

    跟 ModelMismatch 一样是"压根没动手"，不是"跑失败了"：抛出的位置在
    stage_adapt / stage_deploy 之前，一个字节都没往设备写。所以上层要显示
    成绿色提示而不是红色失败，并且问一句要不要强制重跑。

    src  哪个 su 生效的（/debug_ramdisk/su 或 DEV_SU）
    ver  Magisk 版本串（形如 31.1:MAGISK:R），非 Magisk 来路时为 None
    """

    def __init__(self, msg, src=None, ver=None):
        super().__init__(msg)
        self.src = src
        self.ver = ver


class RootWorker(threading.Thread):
    """
    在后台线程里跑完整流程，所有输出通过 queue 交给界面。

    消息格式：
      ("log", text)          追加一行日志
      ("status", text)       更新状态栏
      ("progress", float)    0.0 ~ 1.0
      ("done", ok, summary)  结束
    """

    def __init__(self, adb, tries=3, require_sysadmin=False, do_deploy=True,
                 do_detect=True, q=None, payload=None, with_magisk=False,
                 with_module=False, auto_adapt=False, allow_edl=True,
                 force_model=False, force_rerun=False):
        super().__init__(daemon=True)
        self.adb = adb
        self.tries = max(1, int(tries))
        self.require_sysadmin = bool(require_sysadmin)
        self.do_deploy = do_deploy
        self.do_detect = do_detect
        self.with_magisk = bool(with_magisk)
        self.with_module = bool(with_module)
        self.q = q or queue.Queue()
        self.payload = payload or {}
        # 全自动模式：没成的时候自己去弄一份偏移对的载荷，再试一轮
        self.auto_adapt = bool(auto_adapt)
        self.allow_edl = bool(allow_edl)
        # 机型/内核核对：stage_detect 往里塞，guard() 在动设备之前统一拦。
        # 默认拦死 —— 推错偏移的代价是 kernel panic，不是"重跑一次"。
        self.force_model = bool(force_model)
        # 已经 root 时仍然照跑一遍。只能由用户显式选择（界面上点了「强制重跑」/
        # CLI 加 --force-rerun），不给任何自动路径用 —— 重复跑 exploit 没有收益。
        self.force_rerun = bool(force_rerun)
        self.blockers = []
        self.adapted = None      # 适配成功后 Pilot 的结果
        self.dev_fp = None       # 采过一次就存着，部署阶段别再读一遍 12 万行
        self._stop = threading.Event()
        self.info = {}
        self.already_root = None
        self.su_src = None       # 哪个 su 生效的，precheck_root 要用
        self.magisk_ver = None
        self.skip_exploit = False  # 已有 root 时跳过 stage_root
        self.tag = time.strftime("T%H%M%S")

    # -- 输出 ----------------------------------------------------------------

    def log(self, s="", tag=None):
        """tag: None / "ok" / "bad" / "warn" / "dim"，交给界面着色。"""
        self.q.put(("log", s, tag))

    def status(self, s):
        self.q.put(("status", s))

    def progress(self, v):
        self.q.put(("progress", max(0.0, min(1.0, v))))

    def check_stop(self):
        if self._stop.is_set():
            raise StopRequested()

    def stop(self):
        self._stop.set()

    # -- 阶段 1：检测 --------------------------------------------------------

    def stage_detect(self):
        self.status("检测设备")
        self.log("== 检测设备 ==")
        adb = self.adb

        devs = adb.devices()
        if not devs:
            # 顺带把 USB 总线实况报出来：CLI 没人盯着设备管理器看
            detail = ""
            try:
                import usbtrace
                _k, _m, _h = usbtrace.adb_diag(port=adb.port)
                detail = f"\n  USB 侧实况：{_m}\n  建议：{_h}"
            except Exception:
                pass
            raise AdbError("没有检测到设备。检查数据线、USB 调试开关，"
                           "以及屏幕上是否弹了「允许 USB 调试」的授权框。" + detail)
        target = None
        for d in devs:
            if d["serial"] == adb.serial:
                target = d
                break
        if target is None:
            target = devs[0]
            adb.serial = target["serial"]
        if target["state"] != "device":
            raise AdbError(f"设备状态是 {target['state']}，不是 device。"
                           f"{'请在设备上点「允许」' if target['state']=='unauthorized' else ''}")

        # 连接之后才有意义读属性
        model = adb.getprop("ro.product.model")
        brand = adb.getprop("ro.product.brand")
        rel = adb.getprop("ro.build.version.release")
        sdk = adb.getprop("ro.build.version.sdk")
        disp = adb.getprop("ro.build.display.id")
        fp = adb.getprop("ro.build.fingerprint")
        krel = adb.shell("uname -r", timeout=8)
        up = adb.uptime()
        enf = adb.getenforce()
        boot = adb.getprop("sys.boot_completed")

        self.info = {
            "serial": target["serial"], "model": model, "brand": brand,
            "android": rel, "sdk": sdk, "display": disp, "kernel": krel,
            "fingerprint": fp, "uptime": up, "enforce": enf, "boot": boot,
        }

        self.log(f"  序列号   {target['serial']}")
        self.log(f"  型号     {brand} {model}")
        self.log(f"  系统     Android {rel} (SDK {sdk})  {disp}")
        self.log(f"  内核     {krel}")
        self.log(f"  已开机   {up}s    boot_completed={boot}    SELinux={enf}")

        # 型号/内核核对 —— 62 个偏移和 services.jar 的补丁点全部绑死在这一版。
        # 这里只收集，不刹车：--check 要能跑完、用户也可能只是想看看这是台什么机器。
        # 真正拦人的是 guard()，它卡在"动设备之前"那一条线上。
        self.blockers = []
        if model:
            if TARGET_MODEL not in model and "TabBoox" not in model:
                self.blockers.append(
                    f"型号是 {model}，不是 {TARGET_MODEL} —— 载荷里 62 个偏移只对这一型成立")
        else:
            self.log("  [!] 读不到 ro.product.model，机型无法核对")
        if krel:
            if TARGET_KERNEL not in krel:
                self.blockers.append(
                    f"内核是 {krel}，不是 {TARGET_KERNEL} —— 偏移对不上，跑下去大概率 panic")
        else:
            self.log("  [!] 读不到 uname -r，内核无法核对")
        for b in self.blockers:
            self.log(f"  [!] {b}", "warn")

        # 已经 root 就直说，别让用户白跑一轮。
        # 这里只负责"看清事实"，拦不拦由 precheck_root 决定 —— 检测入口
        # （--check / 界面「检测设备」）不该因为已 root 就报错。
        self.already_root = None
        self.su_src = None
        self.magisk_ver = None
        for cand, label in (("/debug_ramdisk/su", "Magisk"), (DEV_SU, "exploit 临时")):
            rc, out, _ = adb.run(["shell", f"{cand} -c id"], timeout=10)
            if "uid=0" not in out:
                continue
            self.already_root = label
            self.su_src = cand
            self.log(f"  [i] 这台机器已经 root（{label}，{cand}）")
            if label == "Magisk":
                # 版本串从 magisk 二进制自己问。/debug_ramdisk 不在 PATH 里，
                # 所以先按绝对路径试，拿不到再退回裸命令。
                for cmd in (f"{cand} -c /debug_ramdisk/magisk -v",
                            f"{cand} -c magisk -v"):
                    rc2, out2, _ = adb.run(["shell", cmd], timeout=10)
                    v = (out2 or "").strip().splitlines()
                    if v and ":" in v[0]:
                        self.magisk_ver = v[0].strip()
                        break
                self.log(f"      {self.magisk_ver or '版本读不到'}")
            self.log(f"      直接用 `{cand} -c <命令>` 就行，不需要再跑 exploit")
            break
        return True

    # -- 阶段 1.2：机型闸门 --------------------------------------------------

    def guard(self):
        """
        动设备之前的最后一道闸：机型/内核对不上就不许往下走。

        为什么必须有这一道 —— 主流程会做的事按顺序是：往 /data/local/tmp 推
        preload.so → 以它作 LD_PRELOAD 起 exploit → patch kernel 结构体 →
        （勾了 Magisk 时）读 boot.img、打 Magisk patch、dd 回 boot 分区。
        这四步里前两步跑错偏移是内核 panic，第三步跑错是写坏 boot 分区，
        第四步跑错是重启起不来。都不是"再点一次就好"的量级。

        放行条件只有两个：force_model=True（CLI --force-model / 界面勾选），
        或者根本没有 blocker（机型对上了）。
        """
        if not self.do_deploy:
            # 只检测不部署：--check、GUI 的「检测设备」走这条路，
            # 它们一个字节都不往设备写，不该被机型挡住
            return
        if not self.blockers:
            return

        if self.force_model:
            self.log("")
            self.log("  [!] 已显式放行（--force-model / 跳过型号核对），继续", "warn")
            for b in self.blockers:
                self.log("      · " + b, "warn")
            self.log("      偏移不对的后果：内核 panic、boot 分区写坏。", "warn")
            return

        self.log("")
        self.log("=" * 58, "warn")
        self.log("  已停止：这台机器不是本工具适配的机型", "warn")
        self.log("=" * 58, "warn")
        for b in self.blockers:
            self.log("    · " + b, "warn")
        self.log("")
        self.log(f"  本工具只对 {TARGET_MODEL} / 固件 {TARGET_FIRMWARE} / "
                 f"内核 {TARGET_KERNEL} 生成过偏移。", "warn")
        self.log("  继续往下会做：推载荷 → 跑内核 exploit → （勾了 Magisk）写 boot 分区。", "warn")
        self.log("  偏移不对的后果是 kernel panic，严重时要 9008 刷回。", "warn")
        self.log("")
        self.log("  确认要试（例如你自己已经算过新偏移）：", "warn")
        self.log("    命令行：加 --force-model", "warn")
        self.log("    界面：勾「跳过型号核对」再点一键", "warn")
        self.log("  换了固件想正经适配：点「内核适配向导」重新生成载荷。", "warn")
        self.log("=" * 58, "warn")
        raise ModelMismatch("机型/内核不匹配，已阻止继续（要强行走加 --force-model）")

    # -- 阶段 1.3：已 root 就别再跑 ------------------------------------------

    def precheck_root(self):
        """
        设备上已经有可用 su 时，不推载荷、不跑 exploit。

        为什么要单独一道，而不是让 stage_root 自己发现 —— exploit 干的事是
        patch 内核结构体（rt_mutex_waiter 那些），拿到的是同一种 root。
        已经有 root 再 patch 一遍没有任何收益，代价是两轮内核态竞态，
        其中一轮挂住就是 device offline。

        两条来路分开处理，因为持久性完全不同：
          /debug_ramdisk/su  Magisk 提供，重启后还在 —— 再跑纯属多余
          DEV_SU             exploit 自建，本次开机有效 —— 想持久化就得装 Magisk，
                             这时候跳过 exploit 直接进 Magisk 阶段是有意义的

        用户显式要求强制重跑（界面「强制重跑」/ CLI --force-rerun）时全部放行。
        """
        if not self.do_deploy or not self.already_root:
            return

        if self.force_rerun:
            self.log("")
            self.log("  [!] 已要求强制重跑 —— 设备上已有 root，照跑一遍", "warn")
            return

        src = self.su_src or (DEV_SU if self.already_root != "Magisk" else "/debug_ramdisk/su")
        ver = self.magisk_ver or ""

        if self.already_root == "Magisk":
            head = f"设备已经是 Magisk root（{ver or '版本读不到'}，{src}）"
            if self.with_magisk:
                # 再 patch 一次 boot 是拿"当前已 patch 的镜像"当输入，叠补丁
                raise AlreadyRooted(
                    head + "\n"
                    "勾了「安装 Magisk」，但 Magisk 已经在了 —— 再装一遍会拿当前 boot "
                    "重新 patch 一次，叠补丁有写坏 boot 的风险。\n"
                    "要换 Magisk 版本或重打 boot，用 Magisk App 里的「安装 → 直接安装」更稳。",
                    src, ver or None)
            if self.with_module:
                self.skip_exploit = True
                self.log("")
                self.log(f"  [i] {head} —— 跳过 exploit，只更新 AMS 模块")
                return
            raise AlreadyRooted(
                head + "，重启后依然有效，没有必要再跑一遍。", src, ver or None)

        # 来路是 exploit 自建的 su：本次开机有效，重启就没了
        if self.with_magisk:
            self.skip_exploit = True
            self.log("")
            self.log("  [i] 本次开机已有临时 root —— 跳过 exploit，直接用现有 su 装 Magisk")
            return
        raise AlreadyRooted(
            f"本次开机已经有临时 root（{src}），但这是 exploit 给的，重启后就没了。\n"
            "要持久化就勾上「安装 Magisk」再点一次，会跳过 exploit 直接装。",
            src, None)

    # -- 阶段 1.5：自动适配 --------------------------------------------------

    def stage_adapt(self):
        """
        部署前的便宜判断：本地有没有跟这台机器同构建的载荷。

        不碰 boot 分区、不用 EDL、不编译，只读一次 /proc/kallsyms 比对符号
        序列哈希。命中就把路径塞进 payload，后面的 stage_deploy 直接用那份；
        没命中就让 stage_deploy 退回内置载荷（很可能就是这个型号原厂的，
        模板 target.h 本来就是从这台机器上取的）。
        """
        if not self.auto_adapt:
            return
        self.status("匹配载荷")
        self.log("")
        self.log("== 匹配载荷 ==")
        try:
            import adapter as ad
            import fp as fpmod
            targets = ad.list_targets()
            if not targets:
                self.log("  本地没有适配过的内核，先用内置载荷")
                return
            dev_fp = self.dev_fp or fpmod.collect(
                serial=self.adb.serial, adb=self.adb.exe, env=self.adb.env)
            self.dev_fp = dev_fp
            res = fpmod.match(dev_fp, targets)
            self.log(f"  {res['why']}")
            if res["verdict"] == "same_build":
                for t in targets:
                    if t["id"] == res["id"]:
                        so = os.path.join(t["dir"], "preload.so")
                        if os.path.isfile(so):
                            self.payload["preload_so"] = so
                            self.log(f"  用 target「{t['id']}」的载荷（偏移就是这台机器的）")
                        break
            else:
                self.log(f"  {res['advice']}")
        except StopRequested:
            raise
        except Exception as e:
            self.log(f"  [!] 匹配跳过（{e}），用内置载荷")

    def stage_full_adapt(self):
        """
        跑完没成 —— 大概率是偏移不对。走一遍完整适配再给下一轮用。

        这条路会动 boot 分区（只读）：没 root 时进 9008 读，有 root 时直接 dd。
        读完要重新编译 preload.so，全程 3~8 分钟，取决于要不要下 NDK。
        """
        self.status("自动适配内核")
        self.log("")
        self.log("== 自动适配内核 ==")
        self.log("  载荷没跑通。如果这台机器换过固件，内置载荷的 62 个偏移就是错的 ——")
        self.log("  现在按设备当前跑的内核重新生成一份。")

        try:
            import autopilot
        except Exception as e:
            self.log(f"  [!] 适配模块加载失败：{e}")
            return False

        p = autopilot.Pilot(
            self.adb,
            log=self.log,
            status=self.status,
            # 适配阶段的进度映射到总进度的 0.10~0.62 这一段，
            # 不映射的话 A/B 槽都抓一遍会把进度条顶到 100% 再往回掉
            progress=lambda v: self.progress(0.10 + 0.52 * max(0.0, min(1.0, v))),
            stop=self._stop.is_set,
            allow_edl=self.allow_edl,
            dev_fp=self.dev_fp,      # 部署前已经采过指纹，别重复读 12 万行
        )
        try:
            res = p.run()
        except autopilot.PilotStopped:
            raise StopRequested()
        except autopilot.PilotError as e:
            self.log("")
            self.log("  [X] 自动适配没完成：", "warn")
            for line in str(e).splitlines():
                self.log("      " + line, "warn")
            return False
        except Exception as e:
            import traceback
            self.log(f"  [X] 自动适配异常 {type(e).__name__}: {e}", "warn")
            self.log(traceback.format_exc(), "dim")
            return False

        self.adapted = res
        self.payload["preload_so"] = res["preload_so"]
        self.info["adapted_target"] = (res.get("target") or {}).get("id")
        self.log("")
        self.log(f"  适配完成：{res['preload_so']}", "ok")
        self.log(f"  target「{(res.get('target') or {}).get('id')}」已收进本地仓库，"
                 f"下次这台机器不用再编")
        return True

    # -- 阶段 2：部署 --------------------------------------------------------

    def stage_deploy(self):
        self.check_stop()
        self.status("部署载荷")
        self.log("")
        self.log("== 部署载荷 ==")
        adb = self.adb

        so_local = self.payload.get("preload_so")
        picked = None
        if not so_local:
            # 适配向导编过同指纹的载荷就用它 —— 那份的符号偏移对这台机器是对的
            try:
                import adapter
                sym_digest = None
                targets = adapter.list_targets()
                if targets:
                    # 本地有适配过的载荷时，先花几秒读一次符号名序列再决定用哪份。
                    # /proc/kallsyms 的地址可能被 kptr_restrict 清零，但符号名和
                    # 排列顺序是完整的 —— 足以判断"是不是同一次内核构建"。
                    # 拿错偏移去跑是内核 panic，多花这几秒完全值得。
                    try:
                        import fp as fpmod
                        dev_fp = self.dev_fp
                        if dev_fp is None:
                            self.log("  读设备符号序列（判断该用哪份载荷，不需要 root）…")
                            dev_fp = fpmod.collect(serial=adb.serial, adb=adb.exe,
                                                   env=adb.env)
                            self.dev_fp = dev_fp
                        sym_digest = (dev_fp.get("sym") or {}).get("sym_digest")
                        res = fpmod.match(dev_fp, targets)
                        self.log(f"  {res['why']}")
                        if res["verdict"] != "same_build":
                            self.log(f"  {res['advice']}")
                    except Exception as e:
                        self.log(f"  [!] 读符号序列失败，退回指纹/版本匹配：{e}")
                cand, meta = adapter.pick_payload(
                    self.info.get("fingerprint"), self.info.get("kernel"),
                    sym_digest)
                if cand:
                    so_local, picked = cand, meta
            except Exception as e:
                self.log(f"  [!] 查本地适配载荷失败（不影响内置载荷）：{e}")
        if not so_local:
            so_local = resource_path("assets", "payload", "preload.so")
        sh_local = self.payload.get("device_root_sh") or resource_path("assets", "payload", "device_root.sh")
        if not os.path.isfile(so_local):
            raise AdbError(f"包内缺 preload.so（{so_local}）")
        if picked:
            self.log(f"  用适配载荷 {picked.get('id')}（指纹匹配）")
        else:
            self.log("  用内置载荷（指纹未匹配任何已适配 target）")

        adb.shell(f"mkdir -p {DEV_BIN} {DEV_RUNS}", timeout=10)
        adb.push(so_local, f"{DEV_BIN}/preload.so")
        adb.shell(f"chmod 755 {DEV_BIN}/preload.so", timeout=10)

        remote_md5 = adb.shell(f"md5sum {DEV_BIN}/preload.so 2>/dev/null | cut -d' ' -f1", timeout=15)
        local_md5 = md5_of(so_local)
        if remote_md5 and remote_md5 != local_md5:
            raise AdbError(f"preload.so 校验失败：设备 {remote_md5} != 本地 {local_md5}")
        self.log(f"  preload.so -> {DEV_BIN}  md5={remote_md5 or local_md5}  ({os.path.getsize(so_local)//1024} KB)")

        if os.path.isfile(sh_local):
            adb.push(sh_local, f"{DEV_ROOT}/device_root.sh")
            adb.shell(f"chmod 755 {DEV_ROOT}/device_root.sh", timeout=10)
            self.log(f"  device_root.sh -> {DEV_ROOT}   (设备端自持用，不依赖电脑)")

        self.log("  载荷就位")
        return True

    # -- 阶段 3：跑 ----------------------------------------------------------

    def ensure_ready(self):
        """
        设备必须开机满 MIN_UP 秒才能起跑。
        刚开机时 idle 线程正在抢 init_cred 那把锁，写进去就把 cpuidle 打崩。
        """
        up = self.adb.uptime()
        if up is not None and up >= MIN_UP:
            self.log(f"  设备已就绪 uptime={up}s，不重启直接用")
            return True
        self.log(f"  当前 uptime={up}s 不足 {MIN_UP}s，重启并等就绪")
        self.status("重启设备")
        self.adb.run(["reboot"], timeout=15)
        time.sleep(10)

        deadline = time.time() + 240
        while time.time() < deadline:
            self.check_stop()
            up = self.adb.uptime()
            if up is not None and up >= MIN_UP:
                self.log(f"  已就绪 uptime={up}s")
                # 刚够 90 秒时 package manager 可能还在扫包，再给一点余量
                time.sleep(20)
                return True
            time.sleep(3)
        raise AdbError("重启后等不到就绪状态（uptime 一直不到 90s）")

    def launch_round(self, tag):
        runlog = f"{DEV_RUNS}/{tag}.log"
        cmd = (
            f"cd {DEV_BIN} && "
            f"(echo \"START $(date +%s)\" > {runlog}; "
            f"timeout -k 2 {RUN_TIMEOUT} env {CHAIN_ENV} "
            f"LD_PRELOAD=./preload.so /system/bin/sleep {SLEEP_SEC} "
            f">> {runlog} 2>&1; "
            f"echo \"END $(date +%s) RC=$?\" >> {runlog})"
        )
        self.adb.spawn_background(cmd)
        return runlog

    def watch_round(self, runlog, up0, tag):
        """
        盯 uptime / sysname / 日志尾，三种结束条件：
          - uptime 回绕        -> 中途 panic，这轮废
          - 日志出现 END       -> 进程正常结束
          - 出现 FAST_ROOT daemon -> 目标已达成，提前收工（省 ~380 秒）
        """
        t0 = time.time()
        rebooted = False
        daemon = False
        while time.time() - t0 < ROUND_LIMIT:
            self.check_stop()
            time.sleep(3)
            up = self.adb.uptime()
            el = int(time.time() - t0)
            if up is None:
                self.log(f"    t=+{el}s adb 无响应，继续等")
                continue
            if up < up0:
                self.log(f"    t=+{el}s uptime {up0}s -> {up}s 回绕，中途 panic 重启")
                rebooted = True
                break
            sn = self.adb.sysname()
            last = self.adb.shell(f"tail -1 {runlog} 2>/dev/null", timeout=10)
            self.log(f"    t=+{el}s uptime={up}s sysname=[{sn}] last='{last[-70:]}'")
            if last.startswith("END"):
                self.log("    进程正常结束")
                break
            if self.adb.shell(f"grep -c 'FAST_ROOT daemon' {runlog} 2>/dev/null", timeout=10) \
                    not in ("", "0"):
                self.log("    daemon 已起，提前收工")
                daemon = True
                break
        return rebooted, daemon, runlog

    def judge(self, runlog, up0):
        """
        成功三条同时成立（照 root_try.sh）：
          1) uptime 没回绕
          2) exec_probe 的 CapEff 不是 0xc0 / 0
          3) su -c id 输出 uid=0
        返回 (ok, 详情 dict)
        """
        adb = self.adb
        up1 = adb.uptime()
        if up1 is None:
            return False, {"reason": "adb 无响应"}
        if up1 < up0:
            return False, {"reason": f"uptime 回绕 {up0}->{up1}"}

        probe = adb.shell(f"grep -m1 '^CapEff' {DEV_PROBE} 2>/dev/null", timeout=10)
        capeff = probe.split()[1] if len(probe.split()) > 1 else ""
        idout = adb.shell(f'{DEV_SU} -c "id"', timeout=15)
        idline = idout.splitlines()[0] if idout else ""

        # ★ 掩码要在 route 日志里读 bnd=，不能看 exec 后的 CapEff ★
        # 那个内核 execve 的 pP' 落在 inheritable 上，CapEff 只是 inh 的镜像
        bnd = ""
        raw = adb.shell(f"grep -a 'round 3 caps' {runlog} 2>/dev/null | tail -1", timeout=10)
        m = re.search(r"bnd=([0-9a-fA-F]+)", raw)
        if m:
            bnd = m.group(1)

        info = {"capeff": capeff, "id": idline, "bnd": bnd, "uptime": up1}
        if capeff and capeff.lower().endswith(("c0", "00")) and len(capeff) >= 2:
            info["reason"] = f"CapEff={capeff}（能力没抬起来）"
            return False, info
        if not capeff:
            info["reason"] = "没有 exec_probe.txt（caps 阶段没跑到）"
            return False, info
        if "uid=0" not in idline:
            info["reason"] = f"cap 有了但 uid 没到 0：{idline or '(空)'}"
            return False, info
        if self.require_sysadmin and bnd:
            try:
                if not (int(bnd, 16) >> 21) & 1:
                    info["reason"] = "这轮没有 CAP_SYS_ADMIN（KASLR slide 抽签），换一轮"
                    return False, info
            except ValueError:
                pass
        return True, info

    def stage_root(self, base=0.15, span=0.85):
        adb = self.adb
        ok_round = 0
        last_info = {}

        for i in range(1, self.tries + 1):
            self.check_stop()
            self.log("")
            self.log("=" * 58)
            self.log(f"=== 第 {i}/{self.tries} 轮   {time.strftime('%H:%M:%S')}")
            self.progress(base + span * (i - 1) / self.tries)
            self.status(f"第 {i}/{self.tries} 轮")

            self.ensure_ready()
            up0 = adb.uptime()
            if up0 is None:
                self.log("    读不到 uptime，跳过这轮")
                continue
            self.log(f"    起跑 uptime={up0}s  SELinux={adb.getenforce()}")

            # 上一轮的探针必须删掉，否则可能读到旧的"成功"
            adb.shell(f"rm -f {DEV_PROBE} {DEV_ROOT}/root_ok", timeout=10)

            tag = f"{self.tag}_{i}"
            runlog = self.launch_round(tag)
            self.log(f"    已起跑 log={runlog}")

            rebooted, daemon, runlog = self.watch_round(runlog, up0, tag)
            if rebooted:
                self.log("    这轮废了，等设备起来")
                time.sleep(10)
                deadline = time.time() + 180
                while time.time() < deadline:
                    if adb.uptime() is not None and adb.getprop("sys.boot_completed") == "1":
                        break
                    time.sleep(3)
                continue

            ok, info = self.judge(runlog, up0)
            last_info = info
            self.log(f"    判定 CapEff={info.get('capeff') or '<无>'}  "
                     f"bnd={info.get('bnd') or '<无>'}  id={info.get('id') or '<无>'}")
            if info.get("bnd"):
                try:
                    v = int(info["bnd"], 16)
                    self.log(f"    bit21(CAP_SYS_ADMIN)={(v >> 21) & 1}")
                except ValueError:
                    pass
            if ok:
                ok_round = i
                break
            self.log(f"    未成功：{info.get('reason', '未知')}")

        self.progress(0.999)
        if ok_round == 0:
            return False, last_info
        return True, last_info

    def stage_verify(self):
        adb = self.adb
        self.log("")
        self.log("== 验证 ==")
        # 不能写死 DEV_SU：已有 Magisk root 时我们根本不跑 exploit，
        # /data/local/tmp/su 不存在，拿它验证只会输出一片空。
        su = self.pick_su()
        if not su:
            self.log("  没有可用的 su —— 验证跳过", "warn")
            return False
        self.log(f"  用 {su}")
        out = adb.shell(f'{su} -c "id"', timeout=15)
        self.log(f"  {out}")
        caps = adb.shell(f'{su} -c "grep -E ^Cap /proc/self/status"', timeout=15)
        for line in caps.splitlines():
            self.log(f"  {line.strip()}")
        w = adb.shell(f'{su} -c "touch {DEV_ROOT}/root_ok && echo TOUCH_OK"', timeout=15)
        self.log(f"  写 /data/local/tmp: {w}")
        m = adb.shell(f'{su} -c "mkdir -p {DEV_ROOT}/m && mount -t tmpfs tmpfs {DEV_ROOT}/m '
                      f'&& echo MOUNT_OK && umount {DEV_ROOT}/m"', timeout=20)
        self.log(f"  mount tmpfs（需要 CAP_SYS_ADMIN）: {m}")
        return True

    # -- 阶段 4：Magisk / AMS 模块 -------------------------------------------

    def pick_su(self):
        """
        已装 Magisk 时优先用 magisk 的 su；否则用 exploit 自建的那个。
        exploit 的 su 只在本次开机内有效（daemon 随进程死），重启后失效。
        """
        for cand in ("/debug_ramdisk/su", DEV_SU):
            rc, out, _ = self.adb.run(["shell", f"{cand} -c id"], timeout=10)
            if "uid=0" in out:
                return cand
        return None

    def wait_boot(self, limit=300):
        """等设备真正开机完成（不是等 adb 上线）"""
        t0 = time.time()
        while time.time() - t0 < limit:
            self.check_stop()
            if self.adb.getprop("sys.boot_completed") == "1":
                time.sleep(6)          # 让 PackageManager 扫完包
                return True
            time.sleep(3)
        return False

    def reboot_and_wait(self, limit=300):
        self.log("  重启…")
        self.adb.run(["reboot"], timeout=15)
        time.sleep(12)
        ok = self.wait_boot(limit)
        if not ok:
            raise AdbError("重启后等不到开机完成")
        self.log(f"  已开机 uptime={self.adb.uptime()}s")
        return ok

    def stage_magisk(self):
        """
        装 Magisk：备份 boot -> 设备上跑 boot_patch.sh -> dd 写回 -> 装 APK。

        boot_patch.sh 必须在设备上跑：magiskboot 是 aarch64 ELF，Windows 执行不了。
        写回用 dd 而不是 fastboot：ONYX 的 abl 把 flash 命令裁了，
        `fastboot flash boot_b` 一律返回 remote: 'unknown command'（实测）。
        """
        self.check_stop()
        self.status("安装 Magisk")
        self.log("")
        self.log(f"== 安装 Magisk v{MAGISK_VER} ==")
        adb = self.adb

        su = self.pick_su()
        if not su:
            raise AdbError("没有可用的 su，先把 root 拿下再做 Magisk")
        self.log(f"  su: {su}")

        slot = adb.getprop("ro.boot.slot_suffix") or "_a"
        part = f"boot{slot}"
        dev = f"/dev/block/by-name/{part}"
        size = adb.shell(f'{su} -c "blockdev --getsize64 {dev}"', timeout=20)
        if not size.strip().isdigit():
            raise AdbError(f"读不到 {dev}：{size.strip()[:80]}")
        self.log(f"  分区 {part}  {int(size)//1048576} MB  ({dev})")

        # 1) 备份原 boot —— 必须在动分区之前先落到 PC 一份。
        #    只在设备上留一份不算备份：boot 写坏后系统起不来，/data 读不到，
        #    那份文件也就取不出来了（recovery 同样读不到 /data）。
        adb.shell(f'{su} -c "mkdir -p {DEV_MGK} {DEV_KITS}"', timeout=20)
        self.log(f"  备份原 boot（{int(size)//1048576} MB，约 20 秒）…")
        adb.shell(f'{su} -c "dd if={dev} of={DEV_MGK}/stock_boot.img bs=1M"', timeout=600)
        # dd 是 root 身份建的，umask 可能给出 600，shell 拉不动，先放开读
        adb.shell(f'{su} -c "chmod 644 {DEV_MGK}/stock_boot.img"', timeout=20)
        bak = adb.shell(f'{su} -c "md5sum {DEV_MGK}/stock_boot.img"', timeout=60).split()
        if not bak:
            raise AdbError("boot 备份失败（md5 读不到）")

        stamp = time.strftime("%Y%m%d_%H%M%S")
        local_bak = os.path.join(backup_dir(), f"stock_boot{slot}_{stamp}.img")
        self.log("  拉回 PC 留档…")
        adb.pull(f"{DEV_MGK}/stock_boot.img", local_bak)
        lb = md5_of(local_bak)
        if lb != bak[0]:
            raise AdbError(f"备份校验失败：设备 {bak[0]} != 本地 {lb}，已中止（分区未改动）")
        hb = boot_hdr(local_bak)
        if not hb:
            raise AdbError("备份不是合法 boot 镜像（缺 ANDROID! 魔数），已中止（分区未改动）")
        self.log(f"  stock_boot.img md5={lb}  {hb['size']//1048576} MB")
        self.log(f"  已留档 → {local_bak}")
        self.info["stock_boot"] = local_bak

        # 2) 取 Magisk 的工具
        apk = magisk_apk_path()
        if not os.path.isfile(apk):
            raise AdbError(f"找不到内嵌 Magisk APK：{apk}")
        self.log(f"  从 {os.path.basename(apk)} 提取工具（{os.path.getsize(apk)//1048576} MB）")
        tmp = tempfile.mkdtemp(prefix="l5rt_")
        try:
            tools = extract_apk_tools(apk, tmp)
            for name, path in tools.items():
                adb.push(path, f"{DEV_KITS}/{name}")
            adb.shell(f'{su} -c "chmod 755 {DEV_KITS}/*"', timeout=30)
            self.log(f"  已推 {len(tools)} 个文件到 {DEV_KITS}")
            self.check_stop()

            # 3) 上设备打补丁
            self.log("  跑 boot_patch.sh（30~90 秒）…")
            cmd = (f'cd {DEV_MGK} && cp -f {DEV_KITS}/* . && chmod 755 * && '
                   f'KEEPVERITY=true KEEPFORCEENCRYPT=true PATCHVBMETAFLAG=false '
                   f'BOOTMODE=false sh boot_patch.sh stock_boot.img')
            rc, out, err = adb.run(["shell", f'{su} -c "{cmd}"'], timeout=420)
            tail = [l for l in (out or err).splitlines() if l.strip()][-4:]
            for l in tail:
                self.log(f"    | {l}")
            newimg = adb.shell(f"ls -l {DEV_MGK}/new-boot.img 2>/dev/null", timeout=20)
            if "new-boot.img" not in newimg:
                raise AdbError("boot_patch.sh 没产出 new-boot.img")
            self.log(f"  {newimg.strip()}")

            # 3.5) 拉回 PC 并验内核段。
            #      只验 md5 不够：md5 只能证明"写进去的和生成的一样"，
            #      不能证明"生成的是对的"。kernel_size 变了就说明拿错分区
            #      或补丁工具版本不对，这时候写进去必砖，必须在 dd 之前拦住。
            adb.shell(f'{su} -c "chmod 644 {DEV_MGK}/new-boot.img"', timeout=20)
            local_new = os.path.join(backup_dir(), f"new-boot{slot}_{stamp}_magisk.img")
            adb.pull(f"{DEV_MGK}/new-boot.img", local_new)
            hn = boot_hdr(local_new)
            if not hn:
                raise AdbError("生成的 new-boot.img 不是合法 boot 镜像，已中止（分区未改动）")
            if hn["kernel"] != hb["kernel"]:
                raise AdbError(
                    f"kernel 段变了：{hb['kernel']} → {hn['kernel']}。"
                    f"patch 异常或分区拿错，禁止写入（分区未改动）")
            self.log(f"  kernel 未变 {hn['kernel']}；ramdisk {hb['ramdisk']} → "
                     f"{hn['ramdisk']}（{hn['ramdisk'] - hb['ramdisk']:+d}）")
            self.log(f"  已留档 → {local_new}")
            self.info["patched_boot"] = local_new

            # 4) 写回 + 回读校验
            nsz = hn["size"]
            blk = (nsz + 1048575) // 1048576
            self.log(f"  写回 {part}（{nsz//1024} KB）…")
            adb.shell(f'{su} -c "dd if={DEV_MGK}/new-boot.img of={dev} bs=1M conv=fsync"',
                      timeout=600)
            m1 = adb.shell(f"md5sum {DEV_MGK}/new-boot.img", timeout=60).split()
            m2 = adb.shell(
                f'{su} -c "dd if={dev} bs=1M count={blk} 2>/dev/null | head -c {nsz} | md5sum"',
                timeout=300).split()
            self.log(f"  镜像 md5={m1[0] if m1 else '?'}  回读 md5={m2[0] if m2 else '?'}")
            if m1 and m2 and m1[0] != m2[0]:
                raise AdbError(f"回读 md5 不符，写回失败。先别重启，原版备份在 {local_bak}")

            # 5) 补 /data/adb/magisk 运行时
            #    这一步必须在重启前做：setup_magisk_env 只看 busybox 在不在，
            #    不满足就 abort，模块永远不挂载。
            self.log("  补 /data/adb/magisk 运行时…")
            adb.shell(f'{su} -c "mkdir -p /data/adb/magisk"', timeout=20)
            names = " ".join(MAGISK_RUNTIME)
            adb.shell(f'{su} -c "for f in {names}; do cp -f {DEV_KITS}/$f /data/adb/magisk/$f; done"',
                      timeout=60)
            adb.shell(f'{su} -c "chmod 755 /data/adb/magisk/busybox /data/adb/magisk/magiskboot '
                      f'/data/adb/magisk/magiskinit /data/adb/magisk/magisk32 /data/adb/magisk/magisk64 '
                      f'/data/adb/magisk/magiskpolicy /data/adb/magisk/init-ld; '
                      f'chmod 644 /data/adb/magisk/*.sh"', timeout=60)
            cnt = adb.shell(f'{su} -c "ls /data/adb/magisk | wc -l"', timeout=20).strip()
            self.log(f"  /data/adb/magisk 现有 {cnt} 个文件")

            # 6) AMS 修复模块（可选，和 Magisk 同一次重启生效）
            if self.with_module:
                self._prepare_ams_module(su)

            # 7) 装 APK
            self.log("  安装 Magisk App…")
            rc, out, err = adb.run(["install", "-r", "-g", apk], timeout=420)
            line = (out or err).strip().splitlines()
            self.log(f"  {(line[-1] if line else '')[:120]}")
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

        # 8) 重启，Magisk 这时才真正接管
        self.reboot_and_wait()
        adb.shell("pm enable com.topjohnwu.magisk", timeout=20)
        adb.shell(f'{su} -c "pm enable com.topjohnwu.magisk"', timeout=20)

        ps = adb.shell("ps -A 2>/dev/null | grep -c magiskd", timeout=20).strip()
        self.log(f"  magiskd 进程数 {ps}")
        su2 = self.pick_su()
        if su2:
            v = adb.shell(f'{su2} -c "magisk -v"', timeout=20).strip()
            self.log(f"  root 可用：{su2}   magisk {v}")
        else:
            self.log("  [!] 暂时取不到 su —— Magisk 默认策略会拒 shell 请求。")
            self.log("      打开 Magisk App → 超级用户，把「Shell」的开关打开即可。")
        return True

    def _prepare_ams_module(self, su):
        """
        把补丁后的 services.jar 铺成 Magisk 模块。

        必须在重启前完成：模块由 post-fs-data 阶段 magic mount，
        重启后 /system/framework/services.jar 才会变成打过补丁的那份。
        """
        self.check_stop()
        self.log("  准备 AMS 修复模块…")
        adb = self.adb
        remote = f"{DEV_MGK}/services.jar"
        adb.shell(f'{su} -c "cp -f /system/framework/services.jar {remote} && chmod 644 {remote}"',
                  timeout=60)

        tmp = tempfile.mkdtemp(prefix="l5jar_")
        try:
            src = os.path.join(tmp, "services.jar")
            dst = os.path.join(tmp, "services_patched.jar")
            rc, out, err = adb.run(["pull", remote, src], timeout=300)
            if not os.path.isfile(src) or os.path.getsize(src) < 1024:
                raise AdbError(f"拉 services.jar 失败：{(err or out).strip()[:150]}")
            self.log(f"  原版 services.jar {os.path.getsize(src)//1024} KB  md5={md5_of(src)}")
            patch_services_jar(src, dst, log=self.log)

            adb.shell(f'{su} -c "mkdir -p {MOD_DIR}/system/framework"', timeout=30)
            adb.push(dst, f"{MOD_DIR}/system/framework/services.jar")
            prop = os.path.join(tmp, "module.prop")
            with open(prop, "w", encoding="utf-8", newline="\n") as f:
                f.write(MOD_PROP)
            adb.push(prop, f"{MOD_DIR}/module.prop")
            adb.shell(f'{su} -c "chmod -R 755 {MOD_DIR}"', timeout=30)
            chk = adb.shell(f'{su} -c "md5sum {MOD_DIR}/system/framework/services.jar"',
                            timeout=60).split()
            self.log(f"  模块已铺 {MOD_DIR}  md5={chk[0] if chk else '?'}")
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def stage_ams_module_only(self):
        """只装 AMS 模块（Magisk 已经装好了）"""
        self.check_stop()
        self.status("安装 AMS 修复模块")
        self.log("")
        self.log(f"== 安装 AMS 修复模块（{MOD_ID}）==")
        su = self.pick_su()
        if not su:
            raise AdbError("没有可用的 su。先在 Magisk App 里把「超级用户」的 Shell 打开，"
                           "或者重新跑一次 root。")
        self._prepare_ams_module(su)
        self.reboot_and_wait()
        md5 = self.adb.shell("md5sum /system/framework/services.jar", timeout=30).split()
        self.log(f"  重启后 /system/framework/services.jar md5={md5[0] if md5 else '?'}")
        self.adb.shell("pm enable com.topjohnwu.magisk", timeout=20)
        self.log("  完成。Magisk App 现在应该能正常打开了。")
        return True

    # -- 主流程 --------------------------------------------------------------

    def run(self):
        try:
            if self.do_detect:
                self.stage_detect()
                self.progress(0.04)
            # 闸门必须在 stage_adapt / stage_deploy 之前：这两个阶段一个会挑载荷
            # 一个会往设备推文件，从这一步起就不再是"只看不动"了。
            self.guard()

            if not self.do_deploy:
                # 纯检测：界面的「检测设备」也走 run()，但它不该跑到 stage_root ——
                # stage_root 会推载荷、在内核里开跑，那不是"检测"。到这儿已经读完
                # 属性、核过机型、探过 su，剩下的全是"动手"，直接收工。
                self.progress(1.0)
                self.status("检测完成")
                self.q.put(("done", True, {"detect_only": True,
                                           "root": self.already_root,
                                           "magisk": self.magisk_ver}))
                return

            self.precheck_root()        # 已有 root 在这里停，一个字节都不写设备
            if not self.skip_exploit:
                self.stage_adapt()      # 便宜匹配：本地有没有同构建的载荷
                self.stage_deploy()
                self.progress(0.10)

            if self.skip_exploit:
                self.log("")
                self.log("== 已有 root，跳过 exploit ==", "ok")
                ok, info = True, {"reason": "跳过 exploit（设备已有 root）",
                                  "skipped": True}
            else:
                ok, info = self.stage_root(base=0.10, span=0.55)

            # 第一轮全废 + 开了全自动 → 按设备当前内核重新做一份载荷，再来一次。
            # 这一步会读 boot 分区（只读），所以即使判断错了也不会把机器怎么样。
            if not ok and self.auto_adapt:
                self.log("")
                self.log("=" * 58, "warn")
                self.log(f"  {self.tries} 轮都没成 —— 自动适配这台机器自己的内核，再来一次", "warn")
                self.log("=" * 58, "warn")
                if self.stage_full_adapt():
                    self.log("")
                    self.log("== 换用新载荷重新部署 ==")
                    self.stage_deploy()
                    self.progress(0.62)
                    ok, info = self.stage_root(base=0.62, span=0.28)

            if not ok:
                self.status("失败")
                self.log("")
                self.log(f"{self.tries} 轮都没成。原因：{info.get('reason', '未知')}")
                self.log(f"设备端日志在 {DEV_RUNS}/，可以用 adb shell cat 看一下")
                if not self.auto_adapt:
                    self.log("提示：勾上「自动适配」会在失败后按设备当前内核重编载荷再试")
                self.q.put(("done", False, info))
                return

            self.stage_verify()
            self.progress(0.9)

            # root 到手之后的可选阶段
            if self.with_magisk:
                self.stage_magisk()
                self.progress(0.98)
            elif self.with_module:
                self.stage_ams_module_only()
                self.progress(0.98)

            self.progress(1.0)
            self.status("完成")
            self.log("")
            self.log(f"根已拿到：{DEV_SU} -c <命令>")
            if not self.with_magisk:
                self.log("注意：设备重启后 SELinux 回 Enforcing，需要重新跑一次。")
            else:
                self.log("Magisk 已装：重启后 root 由 magiskd 提供，不再依赖 exploit。")
            self.q.put(("done", True, info))
        except StopRequested:
            self.status("已停止")
            self.log("")
            self.log("已按停止。设备上可能还有残留进程，重启一下最干净。")
            self.q.put(("done", False, {"reason": "用户停止"}))
        except ModelMismatch as e:
            # 独立分支：这不是"跑失败了"，是"压根没开始动设备"。
            # 上层要能区分，否则界面会把拦截显示成红色的失败。
            self.status("机型不匹配")
            self.log("")
            self.log(f"[拦截] {e}")
            self.q.put(("done", False, {"reason": str(e), "blocked": True}))
        except AlreadyRooted as e:
            # 同 ModelMismatch：一个字节都没写，不是"跑失败了"。blocked 带具体
            # 原因，界面据此弹"要不要强制重跑"而不是标红。
            self.status("设备已 root")
            self.log("")
            self.log(f"[跳过] {e}")
            self.log("")
            self.log("  确认要重跑：界面点「强制重跑」，或命令行加 --force-rerun", "warn")
            self.q.put(("done", False, {"reason": str(e), "blocked": "already_root",
                                        "su": e.src, "magisk": e.ver}))
        except AdbError as e:
            self.status("出错")
            self.log("")
            self.log(f"[错误] {e}")
            self._log_boot_backups()
            self.q.put(("done", False, {"reason": str(e)}))
        except Exception as e:  # 兜底，别让线程静默死掉
            import traceback
            self.status("出错")
            self.log("")
            self.log(f"[异常] {type(e).__name__}: {e}")
            self.log(traceback.format_exc())
            self._log_boot_backups()
            self.q.put(("done", False, {"reason": f"{type(e).__name__}: {e}"}))

    def _log_boot_backups(self):
        """失败时把已经留档的 boot 路径摆出来 —— 这时候人最需要的就是这个"""
        for key, label in (("stock_boot", "原版 boot"), ("patched_boot", "patched boot")):
            p = self.info.get(key)
            if p and os.path.isfile(p):
                self.log(f"  {label}留档：{p}")


# ----------------------------------------------------------------------------
# 命令行模式（打包冒烟测试用）
# ----------------------------------------------------------------------------

def cli_main(args):
    # 控制台编码在中文 Windows 上经常不是 UTF-8，终端里会显示乱码。
    # 同时落一份 UTF-8 日志，排障时读文件不会失真。
    logdir = os.path.join(app_data_dir(), "logs")
    os.makedirs(logdir, exist_ok=True)
    logpath = os.path.join(logdir, time.strftime("cli_%Y%m%d_%H%M%S.log"))
    logf = open(logpath, "w", encoding="utf-8")
    logf.write(f"# {APP_NAME} {APP_VER}  {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
    logf.write(f"# args={sys.argv[1:]}\n")

    def emit(s=""):
        try:
            print(s, flush=True)
        except Exception:
            pass
        logf.write(s.replace("\n", " ") + "\n")
        logf.flush()

    emit(f"# 日志: {logpath}")

    try:
        exe = install_adb(args.port)
    except AdbError as e:
        emit(f"[-] {e}")
        return 2
    adb = Adb(exe, port=args.port, serial=args.serial, logger=emit)
    try:
        adb.start_server()
    except AdbError as e:
        emit(f"[-] {e}")
        return 2

    q = queue.Queue()

    def drain():
        while True:
            try:
                kind, *rest = q.get_nowait()
            except queue.Empty:
                return
            if kind == "log":
                emit(rest[0])
            elif kind == "status":
                emit(f"[status] {rest[0]}")
            elif kind == "done":
                return

    if args.gplay:
        if not GP_ENABLED:
            emit("[-] 这是普通版 EXE，没有集成 Google Play（也没有内置商店 APK）")
            emit("    用同目录的 Leaf5RootTool_gplay.exe，或 python build.py --gp 单独出一个")
            return 2
        if gplay is None:
            emit("[-] 缺少 gp.py，装商店功能不可用")
            return 2
        base = (os.path.dirname(sys.executable) if getattr(sys, "frozen", False)
                else os.path.dirname(os.path.abspath(__file__)))
        g = gplay.Gp(adb, base_dir=base, log=lambda s: emit("  " + s))
        try:
            r = g.enable(apk=args.apk, reinstall_if_blocked=True)
        except gplay.GpError as e:
            emit(f"[-] {e}")
            return 3
        st = r.get("state")
        if st is not None:
            emit("[i] 商店 " + (f"已装 {st.store_version}" if st.store_installed else "未装")
                 + " / GMS " + ("在" if st.gms_installed else "缺")
                 + f" / 账号 {len(st.accounts)} 个"
                 + " / 前台 " + (st.top or "未知"))
        emit(f"[=] {r['stage']}: {r['detail']}")
        return 0 if r.get("ok") else 1

    if args.check:
        w = RootWorker(adb, tries=1, q=q, do_deploy=False, do_detect=True)

        def safe():
            try:
                w.stage_detect()
            except AdbError as e:
                q.put(("log", f"[错误] {e}"))
            except Exception as e:
                q.put(("log", f"[异常] {type(e).__name__}: {e}"))
            finally:
                q.put(("done", True, {}))

        t = threading.Thread(target=safe, daemon=True)
        t.start()
        t.join(timeout=90)
        drain()
        emit("")
        emit(f"检测完成，日志已存 {logpath}")
        return 0

    w = RootWorker(adb, tries=args.root or 3, require_sysadmin=args.sysadmin,
                   q=q, do_deploy=True, do_detect=True,
                   with_magisk=args.magisk, with_module=args.module,
                   auto_adapt=bool(getattr(args, "auto", False)),
                   allow_edl=not getattr(args, "no_edl", False),
                   force_model=bool(getattr(args, "force_model", False)),
                   force_rerun=bool(getattr(args, "force_rerun", False)))
    w.start()
    ok = False
    while w.is_alive() or not q.empty():
        try:
            kind, *rest = q.get(timeout=0.5)
        except queue.Empty:
            continue
        if kind == "log":
            emit(rest[0])
        elif kind == "status":
            emit(f"[status] {rest[0]}")
        elif kind == "progress":
            pass
        elif kind == "done":
            ok = bool(rest[0])
            break
    emit("")
    emit(f"结束，日志已存 {logpath}")
    return 0 if ok else 1


# ----------------------------------------------------------------------------
# 图形界面
# ----------------------------------------------------------------------------

BG = "#1e1e1e"
BG2 = "#252526"
BG3 = "#2d2d30"
FG = "#d4d4d4"
FG_DIM = "#8a8a8a"
ACCENT = "#0e639c"
ACCENT_H = "#1177bb"
OK_C = "#4ec9b0"
BAD_C = "#f48771"
WARN_C = "#dcdcaa"


class App:
    def __init__(self, root, port=DEFAULT_PORT):
        self.root = root
        self.port = port
        self.adb = None
        self.worker = None
        # 一次性旗标：只在「已 root」弹窗里点了「是」之后置位，_make_worker 取走即清
        self._force_rerun = False
        self.q = queue.Queue()
        self.devices = []

        root.title(f"{APP_NAME} v{APP_VER}")
        # 普通版少了 Google Play 那一行，高度跟着收 28px，否则底部空一条
        root.geometry("900x720" if GP_ENABLED else "900x692")
        root.minsize(780, 580)
        root.configure(bg=BG)

        self._build()
        self._poll()
        self.root.after(300, self.boot)

    # -- 构建界面 ------------------------------------------------------------

    def _build(self):
        pad = {"padx": 12, "pady": 6}

        # 顶部：设备选择
        top = tk.Frame(self.root, bg=BG)
        top.pack(fill="x", **pad)

        tk.Label(top, text="设备", bg=BG, fg=FG, font=("Microsoft YaHei UI", 9)) \
            .pack(side="left")
        self.cmb = ttk.Combobox(top, width=44, state="readonly")
        self.cmb.pack(side="left", padx=8)

        self.btn_refresh = self._btn(top, "刷新设备", self.refresh_devices)
        self.btn_refresh.pack(side="left")

        # 状态行
        st = tk.Frame(self.root, bg=BG)
        st.pack(fill="x", padx=12)
        tk.Label(st, text="状态", bg=BG, fg=FG, font=("Microsoft YaHei UI", 9)).pack(side="left")
        self.lbl_status = tk.Label(st, text="初始化…", bg=BG, fg=FG_DIM,
                                   font=("Microsoft YaHei UI", 9), anchor="w")
        self.lbl_status.pack(side="left", padx=8, fill="x", expand=True)

        # 操作区
        act = tk.Frame(self.root, bg=BG2, highlightthickness=0)
        act.pack(fill="x", padx=12, pady=8)

        row = tk.Frame(act, bg=BG2)
        row.pack(fill="x", padx=10, pady=10)

        self.btn_one = self._btn(row, "一键全自动", self.start_one_click,
                                 primary=True, w=14)
        self.btn_one.pack(side="left")

        self.btn_detect = self._btn(row, "检测", self.start_detect)
        self.btn_detect.pack(side="left", padx=6)
        self.btn_deploy = self._btn(row, "部署载荷", self.start_deploy)
        self.btn_deploy.pack(side="left")
        self.btn_root = self._btn(row, "开始 Root", self.start_root)
        self.btn_root.pack(side="left", padx=6)
        self.btn_stop = self._btn(row, "停止", self.stop, danger=True)
        self.btn_stop.pack(side="left")

        # 选项行
        opt = tk.Frame(act, bg=BG2)
        opt.pack(fill="x", padx=10, pady=(0, 10))

        tk.Label(opt, text="轮数", bg=BG2, fg=FG, font=("Microsoft YaHei UI", 9)).pack(side="left")
        self.spin_tries = tk.Spinbox(opt, from_=1, to=12, width=4,
                                     bg=BG3, fg=FG, insertbackground=FG,
                                     buttonbackground=BG3, relief="flat",
                                     font=("Consolas", 10))
        self.spin_tries.delete(0, "end")
        self.spin_tries.insert(0, "3")
        self.spin_tries.pack(side="left", padx=(6, 18))

        self.var_auto = tk.BooleanVar(value=True)
        tk.Checkbutton(opt, text="自动适配内核（失败后重编载荷）", variable=self.var_auto,
                       bg=BG2, fg=FG, selectcolor=BG3, activebackground=BG2,
                       activeforeground=FG, font=("Microsoft YaHei UI", 9),
                       highlightthickness=0, bd=0).pack(side="left", padx=(0, 16))

        self.var_sysadmin = tk.BooleanVar(value=False)
        tk.Checkbutton(opt, text="要求 CAP_SYS_ADMIN", variable=self.var_sysadmin,
                       bg=BG2, fg=FG, selectcolor=BG3, activebackground=BG2,
                       activeforeground=FG, font=("Microsoft YaHei UI", 9),
                       highlightthickness=0, bd=0).pack(side="left")

        # pack 顺序即从右往左：先放最右的输入框，再放它左边的标签
        self.ent_port = tk.Entry(opt, width=6, bg=BG3, fg=FG, insertbackground=FG,
                                 relief="flat", font=("Consolas", 10))
        self.ent_port.insert(0, str(self.port))
        self.ent_port.pack(side="right")
        tk.Label(opt, text="adb 端口", bg=BG2, fg=FG_DIM,
                 font=("Microsoft YaHei UI", 9)).pack(side="right", padx=(0, 8))

        # 第二行：Magisk 与修复模块
        opt2 = tk.Frame(act, bg=BG2)
        opt2.pack(fill="x", padx=10, pady=(0, 10))

        self.var_magisk = tk.BooleanVar(value=False)
        self.var_module = tk.BooleanVar(value=False)

        self.chk_magisk = tk.Checkbutton(
            opt2, text="安装 Magisk（patch boot + 装 App，会重启一次）",
            variable=self.var_magisk, command=self._on_magisk_toggle,
            bg=BG2, fg=FG, selectcolor=BG3, activebackground=BG2, activeforeground=FG,
            font=("Microsoft YaHei UI", 9), highlightthickness=0, bd=0)
        self.chk_magisk.pack(side="left")

        self.chk_module = tk.Checkbutton(
            opt2, text="装 AMS 修复模块（修 Magisk App 卡在启动图）",
            variable=self.var_module,
            bg=BG2, fg=FG, selectcolor=BG3, activebackground=BG2, activeforeground=FG,
            font=("Microsoft YaHei UI", 9), highlightthickness=0, bd=0)
        self.chk_module.pack(side="left", padx=(18, 0))

        # 自动适配时能不能走 9008。开着是默认：没 root 时这是唯一能拿到
        # boot 分区内容的路。关掉就只有「已 root 的机器能自动适配」。
        self.var_edl = tk.BooleanVar(value=True)
        tk.Checkbutton(
            opt2, text="允许 9008(EDL) 读分区", variable=self.var_edl,
            bg=BG2, fg=FG, selectcolor=BG3, activebackground=BG2,
            activeforeground=FG, font=("Microsoft YaHei UI", 9),
            highlightthickness=0, bd=0).pack(side="left", padx=(18, 0))

        # 第三行：换内核后的适配入口。不参与 root 流程，单独开窗
        opt3 = tk.Frame(act, bg=BG2)
        opt3.pack(fill="x", padx=10, pady=(0, 10))
        tk.Label(opt3, text="换了固件 / 内核？", bg=BG2, fg=FG_DIM,
                 font=("Microsoft YaHei UI", 9)).pack(side="left")
        self.btn_adapter = self._btn(opt3, "内核适配向导", self.open_adapter, w=14)
        self.btn_adapter.pack(side="left", padx=6)
        self.lbl_targets = tk.Label(opt3, text="", bg=BG2, fg=FG_DIM,
                                    font=("Microsoft YaHei UI", 8))
        self.lbl_targets.pack(side="left", padx=6)

        # 机型闸门的手动放行开关。默认不勾 —— 型号/内核对不上时一键全自动
        # 会停在检测之后，一步都不往设备写。勾了才继续，用 warn 色标出来。
        self.var_force = tk.BooleanVar(value=False)
        tk.Checkbutton(
            opt3, text="跳过型号核对（偏移不对会 panic）", variable=self.var_force,
            bg=BG2, fg=WARN_C, selectcolor=BG3, activebackground=BG2,
            activeforeground=WARN_C, font=("Microsoft YaHei UI", 9),
            highlightthickness=0, bd=0).pack(side="right")

        # 第四行：Google Play。和 root 完全独立的一条腿 ——
        # 装商店不需要先 root，root 过的机器也不需要再走一遍。
        # 只有集成版才画这一行：普通版没有内置 APK，留个按钮只会点了报错。
        self.btn_gplay = None
        self.lbl_gplay = None
        if GP_ENABLED:
            opt4 = tk.Frame(act, bg=BG2)
            opt4.pack(fill="x", padx=10, pady=(0, 10))
            tk.Label(opt4, text="谷歌服务？", bg=BG2, fg=FG_DIM,
                     font=("Microsoft YaHei UI", 9)).pack(side="left")
            self.btn_gplay = self._btn(opt4, "装 Google Play", self.start_gplay, w=14)
            self.btn_gplay.pack(side="left", padx=6)
            self.lbl_gplay = tk.Label(opt4, text="", bg=BG2, fg=FG_DIM,
                                      font=("Microsoft YaHei UI", 8))
            self.lbl_gplay.pack(side="left", padx=6)

        # 进度条。日志区是 expand=True 的，不给进度条固定高度就会被挤成一条线
        pf = tk.Frame(self.root, bg=BG, height=12)
        pf.pack(fill="x", padx=12, pady=(6, 2))
        pf.pack_propagate(False)
        self.pb = ttk.Progressbar(pf, mode="determinate", maximum=100)
        self.pb.pack(fill="both", expand=True)

        # 日志
        lf = tk.Frame(self.root, bg=BG)
        lf.pack(fill="both", expand=True, padx=12, pady=8)
        self.txt = tk.Text(lf, bg="#141414", fg="#c8c8c8", insertbackground=FG,
                           relief="flat", wrap="none", font=("Consolas", 9),
                           state="disabled", height=18)
        sb = tk.Scrollbar(lf, command=self.txt.yview, bg=BG3, troughcolor=BG2)
        self.txt.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        self.txt.pack(side="left", fill="both", expand=True)
        self.txt.tag_config("ok", foreground=OK_C)
        self.txt.tag_config("bad", foreground=BAD_C)
        self.txt.tag_config("warn", foreground=WARN_C)
        self.txt.tag_config("dim", foreground=FG_DIM)

        # 底栏
        foot = tk.Frame(self.root, bg=BG)
        foot.pack(fill="x", padx=12, pady=(0, 8))
        # 适用机型放最前面：这行是唯一会跟截图一起传出去的东西，
        # 端口和载荷大小写后面
        self.lbl_foot = tk.Label(
            foot,
            text=(f"仅适用 {TARGET_MODEL} · 固件 {TARGET_FIRMWARE} · 内核 {TARGET_KERNEL}"
                  f"   |   adb 端口 {self.port} · 载荷 preload.so 2.4MB"),
            bg=BG, fg=FG_DIM, font=("Microsoft YaHei UI", 8))
        self.lbl_foot.pack(side="left")

    def _btn(self, parent, text, cmd, primary=False, danger=False, w=9):
        bg = ACCENT if primary else (BG3 if not danger else "#5a1d1d")
        fg = "#ffffff" if primary else FG
        b = tk.Button(parent, text=text, command=cmd, bg=bg, fg=fg,
                      activebackground=ACCENT_H if primary else BG3,
                      activeforeground="#ffffff" if primary else FG,
                      relief="flat", bd=0, width=w, height=1,
                      font=("Microsoft YaHei UI", 9), cursor="hand2")
        return b

    # -- 日志 ----------------------------------------------------------------

    def log(self, s="", tag=None):
        self.txt.configure(state="normal")
        self.txt.insert("end", s + "\n", tag or ())
        self.txt.see("end")
        self.txt.configure(state="disabled")

    def set_status(self, s, color=None):
        self.lbl_status.configure(text=s, fg=color or FG_DIM)

    # -- 消息泵 --------------------------------------------------------------

    def _poll(self):
        try:
            while True:
                kind, *rest = self.q.get_nowait()
                if kind == "log":
                    txt = rest[0]
                    # 生产者显式给的 tag 优先；没给才按关键字猜
                    tag = rest[1] if len(rest) > 1 else None
                    if not tag:
                        if "[错误]" in txt or "[异常]" in txt or "未成功" in txt or "[!]" in txt:
                            tag = "bad"
                        elif "根已拿到" in txt or "== 验证" in txt or "TOUCH_OK" in txt:
                            tag = "ok"
                        elif txt.startswith("    t=+"):
                            tag = "dim"
                    self.log(txt, tag)
                elif kind == "status":
                    self.set_status(rest[0])
                elif kind == "progress":
                    self.pb["value"] = rest[0] * 100
                elif kind == "done":
                    self._on_done(bool(rest[0]), rest[1] if len(rest) > 1 else {})
                elif kind == "gplay":
                    self._on_gplay(rest[0])
        except queue.Empty:
            pass
        self.root.after(120, self._poll)

    def _on_done(self, ok, info):
        self._busy(False)
        if ok:
            if info.get("detect_only"):
                self._show_detect_verdict(info)
                return
            self.set_status("已完成 —— root 可用", OK_C)
            return
        if info.get("blocked") == "already_root":
            # 不是失败：一个字节都没写。用绿色 + 让人决定。
            self.set_status("设备已 root —— 没有执行", OK_C)
            self._offer_rerun(info)
            return
        reason = str(info.get("reason", "")).splitlines()
        self.set_status(f"未完成：{reason[0]}" if reason else "未完成", BAD_C)

    def _show_detect_verdict(self, info):
        """检测收尾：把 su 的来路直接写在状态栏，别让人再去翻日志。"""
        root = info.get("root")
        ver = info.get("magisk") or ""
        if root == "Magisk":
            self.set_status(f"检测完成 —— 已 root（Magisk {ver or '版本未知'}）", OK_C)
        elif root:
            self.set_status(f"检测完成 —— 本次开机有临时 root（{root}），重启失效", WARN_C)
        else:
            self.set_status("检测完成 —— 未 root，点「一键全自动」开始", FG_DIM)

    def _offer_rerun(self, info):
        """
        已 root 被拦下来时的人工裁决。默认「否」—— 不动是最安全的一档。

        这里必须在 worker 线程结束之后弹：done 是从队列里取的，run() 已经
        return，所以模态框不会跟工作线程抢设备。
        """
        if not messagebox:
            return
        src = info.get("su") or ""
        ver = info.get("magisk") or ""
        body = (f"设备已经 root：{src}" + (f"  {ver}" if ver else "") + "\n\n"
                "「是」＝ 照样重跑一遍（重新推载荷、跑 exploit，有内核 panic 的可能）\n"
                "「否」＝ 什么都不做，到此为止\n\n"
                "只想更新 AMS 修复模块：点「否」，勾上「装 AMS 修复模块」，再点一次一键 "
                "—— 那条路会自动跳过 exploit。")
        if messagebox.askyesno("设备已经 root", body):
            self._force_rerun = True
            self.log("")
            self.log("== 按你的选择强制重跑一遍 ==", "warn")
            self.start_one_click()
        else:
            self.log("")
            self.log("已跳过：设备本来就是 root，没有需要做的事。", "ok")

    # -- 忙碌态 --------------------------------------------------------------

    def _busy(self, b):
        state = "disabled" if b else "normal"
        ws = [self.btn_one, self.btn_detect, self.btn_deploy, self.btn_root]
        # 普通版没有这个按钮，属性是 None，塞进列表会炸
        if self.btn_gplay is not None:
            ws.append(self.btn_gplay)
        for w in ws:
            w.configure(state=state)
        for w in (self.chk_magisk, self.chk_module):
            w.configure(state=state)
        self.btn_refresh.configure(state=state)
        if b:
            self.pb["value"] = 0

    # -- 启动 ----------------------------------------------------------------

    def boot(self):
        try:
            exe = install_adb(self.port)
            self.adb = Adb(exe, port=self.port)
            self.adb.start_server()
            self.log(f"adb 就绪  {exe}", "dim")
            self.log(f"server 端口 {self.port}", "dim")
            self.set_status("已就绪，点「一键 Root」开始")
        except Exception as e:
            self.set_status("adb 初始化失败", BAD_C)
            self.log(f"[错误] {e}")
        self.refresh_devices()
        self.refresh_targets()

    # -- 按钮 ----------------------------------------------------------------

    def refresh_devices(self):
        if not self.adb:
            return
        try:
            devs = self.adb.devices()
        except Exception as e:
            self.log(f"[错误] 读设备列表失败: {e}")
            return

        if not devs:
            # 空表有两种成因：设备真不在，或 server 状态坏了（换过端口、
            # 被别的 daemon 抢走 USB 句柄）。后者重启 server 就能恢复，
            # 所以自动试一次 —— 但限频，免得连点「刷新」反复打断。
            now = time.time()
            if now - getattr(self, "_last_recover", 0) > 10:
                self._last_recover = now
                self.adb.kill_server()
                try:
                    self.adb.start_server()
                    devs = self.adb.devices()
                    if devs:
                        self.log("重启 adb server 后恢复", "ok")
                except AdbError as e:
                    self.log(f"adb server 重启失败: {e}", "dim")

        self.devices = devs
        items = []
        for d in devs:
            label = f"{d['serial']}   [{d['state']}]"
            if d["model"]:
                label += f"   {d['model']}"
            items.append(label)
        self.cmb["values"] = items
        if items:
            if not self.cmb.get():
                self.cmb.current(0)
            self.log(f"发现 {len(items)} 台设备", "dim")
        else:
            self.set_status("没有设备。插线、开 USB 调试、屏幕上点「允许」")
            self.log("没有检测到设备", "bad")
            self._log_adb_diag()

    def _log_adb_diag(self):
        """
        设备列表为空时，把「卡在哪一环」直接说清楚。

        adb 的 `devices` 在下面三种情况下都返回空表，光看 adb 分不出来：
          · 线只供电 / 口不通     → 总线上压根没有节点
          · ADB 接口缺驱动        → 节点在，problem=28
          · 设备停在 9008         → 节点在，但不是 ADB
        所以这里绕过 adb，直接问 SetupAPI 要总线实况。
        """
        try:
            import usbtrace
            kind, msg, hint = usbtrace.adb_diag(port=self.adb.port if self.adb else None)
        except Exception as e:
            self.log(f"（USB 诊断没跑起来：{e}）", "dim")
            return
        tag = {"no_usb": "bad", "adb_nodriver": "bad",
               "in_edl": "warn", "qc_other": "warn"}.get(kind, "dim")
        self.log(f"诊断 · {msg}", tag)
        self.log(f"      → {hint}", "dim")

    def _selected_serial(self):
        idx = self.cmb.current()
        if 0 <= idx < len(self.devices):
            return self.devices[idx]["serial"]
        return None

    def _on_magisk_toggle(self):
        """
        勾了 Magisk 就自动勾上模块：ONYX 的 AMS 有个 NPE，
        不修的话 Magisk App 装完也起不来（root 本身是好的，但看不到界面）。
        """
        if self.var_magisk.get():
            self.var_module.set(True)

    def open_adapter(self):
        """开「内核适配向导」。不参与 root 流程，独立窗口"""
        try:
            import adapter_ui
        except Exception as e:
            messagebox.showerror("启不来", f"缺适配模块：{e}")
            return
        w = getattr(self, "_adapter_win", None)
        try:
            if w is not None and w.win.winfo_exists():
                w.win.deiconify()
                w.win.lift()
                w.win.focus_force()
                return
        except Exception:
            pass
        try:
            self._adapter_win = adapter_ui.open_window(self.root, self)
        except Exception as e:
            messagebox.showerror("启不来", str(e))

    def refresh_targets(self):
        """刷新"已装几份适配载荷"的提示，并按有没有可用载荷调整主按钮的主次。

        这一版仓库里不带 preload.so（编译产物，62 个偏移只对原厂 4.2.3 成立），
        从源码 build 出来的人包里是空的 —— 那种情况下"一键全自动"点了必然在
        部署那一步失败（三级回落全落空），真正该先做的是适配向导。
        所以这里不是把向导固定排第一位（开箱即用的机器不需要它，排在前面
        反而让人白等 700MB NDK），而是按当前有没有载荷动态调主次：

            bundled      包内有 .so        → 一键为主，向导保持角落
            targets_only 包内无、targets 目录有 → 一键可用（stage_adapt 会挑中）
            none         两者都无            → 向导升为主按钮并标「首次必做」
        """
        try:
            import adapter
            ts = adapter.list_targets()
        except Exception:
            ts = []
        n = len(ts)
        if hasattr(self, "lbl_targets"):
            self.lbl_targets.configure(
                text=f"已装 {n} 份适配载荷" if n else "还没有适配载荷",
                fg=OK_C if n else FG_DIM)

        bundled = os.path.isfile(resource_path("assets", "payload", "preload.so"))
        self._apply_payload_state("bundled" if bundled else
                                  ("targets_only" if n else "none"), n)

    def _apply_payload_state(self, state, n=0):
        """按载荷状态调按钮主次 + 状态栏提示。三种状态见 refresh_targets 的注释。"""
        if not hasattr(self, "btn_one") or not hasattr(self, "btn_adapter"):
            return
        self._payload_state = state

        if state == "none":
            # 没有任何载荷：向导才是真正的第一步。主按钮换成向导，
            # 一键全自动降成普通样式 —— 不 disable，用户仍可自己硬闯
            self.btn_adapter.configure(
                text="① 内核适配向导（首次必做）", width=24,
                bg=ACCENT, fg="#ffffff",
                activebackground=ACCENT_H, activeforeground="#ffffff")
            self.btn_one.configure(
                text="一键全自动", bg=BG3, fg=FG_DIM,
                activebackground=BG3, activeforeground=FG_DIM)
            self.set_status("本包未内置载荷 —— 先点左侧「内核适配向导」现编，"
                            "编完再点一键全自动", WARN_C)
        else:
            self.btn_adapter.configure(
                text="内核适配向导", width=14,
                bg=BG3, fg=FG,
                activebackground=BG3, activeforeground=FG)
            self.btn_one.configure(
                text="一键全自动", bg=ACCENT, fg="#ffffff",
                activebackground=ACCENT_H, activeforeground="#ffffff")
            if state == "targets_only":
                self.set_status(f"载荷来自适配目录（{n} 份），可直接一键全自动", OK_C)
            # bundled 不动状态栏：那句「已就绪」是启动流程写的，别盖掉

    def _make_worker(self, **kw):
        serial = self._selected_serial()
        port = int(self.ent_port.get().strip() or self.port)
        if port != self.adb.port:
            # 先按旧端口把 daemon 收掉：留着的话它继续握着 USB 句柄，
            # 新端口那个 server 就会一直列不出设备（两个 daemon 抢同一根线）
            self.adb.kill_server()
            self.adb.port = port
            self.adb.env["ANDROID_ADB_SERVER_PORT"] = str(port)
            try:
                self.adb.start_server()
            except AdbError as e:
                self.log(f"[错误] 切端口失败: {e}")
        if serial:
            self.adb.serial = serial
        # 所有入口（检测/部署/一键/轮次）都从这里过，放行开关在这里统一注入，
        # 免得将来新加一条路径忘了带 force_model 又被闸门挡住
        kw.setdefault("force_model", bool(getattr(self, "var_force", None)
                                          and self.var_force.get()))
        # 同上：强制重跑也在这里统一注入，且读一次就复位 —— 否则后面点任何一个
        # 按钮都会莫名继承"无视已 root 状态"
        kw.setdefault("force_rerun", self._take_force_rerun())
        w = RootWorker(self.adb, q=self.q, **kw)
        return w

    def _take_force_rerun(self):
        v = bool(getattr(self, "_force_rerun", False))
        self._force_rerun = False
        return v

    def start_detect(self):
        self._start_worker(do_detect=True, do_deploy=False, tries=1)

    def start_deploy(self):
        self._start_worker(do_detect=True, do_deploy=True, tries=1, deploy_only=True)

    def start_root(self):
        try:
            n = int(self.spin_tries.get())
        except ValueError:
            n = 3
        self._start_worker(do_detect=True, do_deploy=True, tries=n,
                           require_sysadmin=self.var_sysadmin.get())

    # -- Google Play ---------------------------------------------------------

    def _gp_base(self):
        """
        APK 的查找根。onefile 模式下 sys._MEIPASS 是临时解包目录，
        用户往那儿放东西下次就没了，所以用 EXE 所在目录。
        """
        if getattr(sys, "frozen", False):
            return os.path.dirname(sys.executable)
        return os.path.dirname(os.path.abspath(__file__))

    def start_gplay(self):
        """
        装商店 / 启用商店。不碰 root，也不写 gms_enable（见 gp.py 顶部说明）。

        整个动作分两段：能一条命令跑完的（装、拉起）现在做；
        需要人去设备上登录的（ONYX 的开关只在账号验证通过时写），
        把页面拉起来就交回给用户。
        """
        if gplay is None:
            self.log("[错误] 缺少 gp.py，装商店功能不可用", "bad")
            return
        if not self.adb:
            self.log("[错误] adb 还没初始化", "bad")
            return
        if not self._selected_serial():
            self.refresh_devices()
        if not self._selected_serial():
            self.log("[错误] 没有可用设备，无法开始", "bad")
            return
        self.adb.serial = self._selected_serial()

        self._busy(True)
        self.lbl_gplay.configure(text="检查中…", fg=FG_DIM)
        self.log("")
        self.log("== Google Play：探测 → 按需安装 → 拉起验证 ==", "ok")
        base = self._gp_base()

        def work():
            try:
                g = gplay.Gp(self.adb, base_dir=base,
                             log=lambda s: self.q.put(("log", "  " + s, "dim")))
                r = g.enable(reinstall_if_blocked=True)
            except Exception as e:
                r = {"ok": False, "stage": "failed",
                     "detail": f"{type(e).__name__}: {e}",
                     "state": None, "need_manual": False}
            self.q.put(("gplay", r))

        threading.Thread(target=work, daemon=True).start()

    def _on_gplay(self, r):
        self._busy(False)
        st = r.get("state")
        stage = r.get("stage") or "failed"
        detail = str(r.get("detail") or "")

        if st is not None:
            self.log("  现状：商店 "
                     + (f"已装 {st.store_version}" if st.store_installed else "未装")
                     + " / GMS " + ("在" if st.gms_installed else "缺")
                     + " / 账号 " + f"{len(st.accounts)} 个"
                     + " / 前台 " + (st.top or "未知"), "dim")
        for line in detail.splitlines():
            if line.strip():
                self.log("  " + line, "dim")

        if r.get("ok"):
            self.lbl_gplay.configure(text="商店可用", fg=OK_C)
            self.set_status("Google Play 已可用", OK_C)
            return

        if stage == "need_login":
            self.lbl_gplay.configure(text="等设备上登录", fg=WARN_C)
            self.set_status("去设备上登录 Google 账号", WARN_C)
            if messagebox:
                messagebox.showinfo(
                    "登录 Google 账号",
                    "已在设备上打开「添加账号」页。\n\n"
                    "登录 Google 账号并完成验证后，ONYX 会自己打开 Play 商店的开关，\n"
                    "再点一次「装 Google Play」就能确认。")
            return

        self.lbl_gplay.configure(text=f"未完成（{stage}）", fg=BAD_C)
        self.set_status(f"Google Play 未完成：{stage}", BAD_C)

    def start_one_click(self):
        """
        一条命令跑完全程：
          等设备 → 检测 → 匹配载荷 → 部署 → 跑链 → （没成）自动适配再跑 → Magisk
        中间只在两种情况下停：设备不在线（等人插线/点授权）、适配拿到的东西
        自证不上（宁可停也不拿错偏移去崩内核）。
        """
        try:
            n = int(self.spin_tries.get())
        except ValueError:
            n = 3
        auto = self.var_auto.get()
        if auto:
            # 全自动模式默认把 Magisk 一起装上 —— 不然重启又要重跑一遍 exploit。
            # set() 不触发 command，所以要手工调一次连带勾模块。
            self.var_magisk.set(True)
            self._on_magisk_toggle()
        self.log("")
        self.log(f"== 一键全自动：检测 → 匹配 → 部署 → 最多 {n} 轮"
                 f"{' → 失败则适配重试' if auto else ''}"
                 f"{' → Magisk' if self.var_magisk.get() else ''} ==", "ok")
        self._start_worker(do_detect=True, do_deploy=True, tries=n,
                           require_sysadmin=self.var_sysadmin.get(),
                           auto_adapt=auto)

    def _start_worker(self, do_detect=True, do_deploy=True, tries=3,
                      require_sysadmin=False, deploy_only=False,
                      auto_adapt=False):
        if self.worker and self.worker.is_alive():
            self.log("已有任务在跑", "warn")
            return
        if not self.adb:
            self.log("[错误] adb 还没初始化", "bad")
            return
        if not self._selected_serial():
            # 多半是刚插上还没刷 —— 先自己刷一次，省得用户来回点按钮
            self.refresh_devices()
        if not self._selected_serial():
            self.log("[错误] 没有可用设备，无法开始（上面一行诊断说明卡在哪一环）", "bad")
            return

        self._busy(True)
        if deploy_only:
            # 只部署：跑完检测+部署就收工，不进入轮次
            w = self._make_worker(do_detect=do_detect, do_deploy=True, tries=0)
            w.stage_root = lambda: (True, {"reason": "仅部署"})
        else:
            mag = self.var_magisk.get()
            mod = self.var_module.get()
            if mod and not mag:
                self.log("[i] 只装模块：Magisk 必须已经装好，否则模块不会加载", "warn")
            w = self._make_worker(do_detect=do_detect, do_deploy=do_deploy, tries=tries,
                                  require_sysadmin=require_sysadmin,
                                  with_magisk=mag, with_module=mod,
                                  auto_adapt=auto_adapt,
                                  allow_edl=self.var_edl.get())
        self.worker = w
        w.start()

    def stop(self):
        if self.worker and self.worker.is_alive():
            self.log("请求停止…", "warn")
            self.worker.stop()

    def on_close(self):
        try:
            if self.worker and self.worker.is_alive():
                self.worker.stop()
                time.sleep(0.2)
            if self.adb:
                self.adb.kill_server()
        except Exception:
            pass
        self.root.destroy()


def gui_main(port):
    if tk is None:
        print("这个 Python 没带 tkinter，只能用命令行模式：--check / --root N")
        return 2
    root = tk.Tk()
    # 深色下 ttk 控件（进度条/下拉框）需要显式主题
    style = ttk.Style()
    try:
        style.theme_use("clam")
    except Exception:
        pass
    style.configure("TProgressbar", troughcolor="#3c3c3c", background=ACCENT,
                    bordercolor="#3c3c3c", lightcolor=ACCENT, darkcolor=ACCENT,
                    thickness=12)
    style.configure("TCombobox", fieldbackground=BG3, background=BG3, foreground=FG,
                    arrowcolor=FG)
    style.map("TCombobox", fieldbackground=[("readonly", BG3)],
              foreground=[("readonly", FG)])
    app = App(root, port=port)
    root.protocol("WM_DELETE_WINDOW", app.on_close)
    root.mainloop()
    return 0


def attach_console():
    """
    --windowed 打包后进程没有 stdout/stderr。
    从 cmd/PowerShell 启动并带 CLI 参数时，把自己接回父控制台，
    否则 --check / --root 的输出全丢了（排障时最要命）。
    """
    if os.name != "nt":
        return
    try:
        import ctypes
        k = ctypes.windll.kernel32
        if k.AttachConsole(-1):
            # 控制台默认是 GBK 代码页，直接写 UTF-8 会变成乱码
            k.SetConsoleOutputCP(65001)
            k.SetConsoleCP(65001)
            sys.stdout = open("CONOUT$", "w", encoding="utf-8", buffering=1,
                              errors="replace")
            sys.stderr = open("CONOUT$", "w", encoding="utf-8", buffering=1,
                              errors="replace")
            sys.stdin = open("CONIN$", "r", encoding="utf-8", errors="replace")
    except Exception:
        pass


def _edl_log_open():
    """EDL 分支的日志文件。行缓冲：进程被外部杀掉也留得下最后一行。"""
    base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
    d = os.path.join(base, "Leaf5RootTool", "logs")
    try:
        os.makedirs(d, exist_ok=True)
    except Exception:
        d = os.getcwd()
    p = os.path.join(d, "edl_%s.log" % time.strftime("%Y%m%d_%H%M%S"))
    return p, open(p, "w", encoding="utf-8", errors="replace", buffering=1)


def _echo_log(logp, tail=200):
    """
    退出时把日志回显到控制台。

    只是在会话已经结束之后尽力而为：这一步即便卡住也只是退出慢，
    不会像会话中途阻塞那样把 USB 通讯拖死。所以放在最后、只取尾部。
    """
    if os.name != "nt":
        try:
            with open(logp, encoding="utf-8", errors="replace") as f:
                sys.__stdout__.write("".join(f.readlines()[-tail:]))
        except Exception:
            pass
        return
    try:
        with open(logp, encoding="utf-8", errors="replace") as f:
            body = "".join(f.readlines()[-tail:])
        with open("CONOUT$", "w", encoding="utf-8", errors="replace") as c:
            c.write(body)
            c.flush()
    except Exception:
        pass


def main():
    ap = argparse.ArgumentParser(description=APP_NAME)
    ap.add_argument("--check", action="store_true", help="只检测设备，不改动")
    ap.add_argument("--gplay", action="store_true",
                    help="安装/启用 Google Play（不碰 root）")
    ap.add_argument("--apk", default=None,
                    help="--gplay 时指定商店 APK；不给就按 assets/apk -> apk 顺序找")
    ap.add_argument("--root", type=int, metavar="N", help="无界面跑 N 轮")
    ap.add_argument("--sysadmin", action="store_true", help="要求 CAP_SYS_ADMIN")
    ap.add_argument("--magisk", action="store_true", help="顺手装 Magisk（会 patch boot 并重启）")
    ap.add_argument("--module", action="store_true", help="装/更新 AMS 修复模块")
    ap.add_argument("--auto", action="store_true",
                    help="全自动：等设备 → 匹配载荷 → 失败自动适配 → （带 --magisk）装 Magisk")
    ap.add_argument("--no-edl", action="store_true",
                    help="自动适配时禁止走 9008（设备会黑屏重启）")
    ap.add_argument("--edl", nargs="?", const="env", default=None,
                    metavar="env|slot|gpt|dump",
                    help="EDL 链路自检与单独操作：env(默认)/slot/gpt/dump，"
                         "全程只读，不改设备")
    ap.add_argument("--serial", default=None, help="指定设备序列号")
    ap.add_argument("--force-model", action="store_true",
                    help="型号或内核与本工具适配的不一致时仍然继续。"
                         "默认会拦下来 —— 偏移绑死在 Leaf5 / 4.2.3-rel_0928 / 4.19.157，"
                         "别的机器上跑错偏移是 kernel panic")
    ap.add_argument("--force-rerun", action="store_true",
                    help="设备上已经有 su 时也照样重跑一遍 exploit。"
                         "默认会跳过（已有 root 再 patch 一遍内核没有收益）")
    ap.add_argument("--port", type=int, default=DEFAULT_PORT, help=f"adb server 端口，默认 {DEFAULT_PORT}")
    # 用 known 版：`--edl dump -o 某个目录` 里 -o 属于 edl 子命令，
    # 主 parser 不认识它。用 parse_args 会直接 rc=2 拒掉，看起来像
    # 「这个功能不存在」。剩下的原样透传给 edlman。
    args, extra = ap.parse_known_args()
    if extra and not args.edl:
        ap.error("unrecognized arguments: %s" % " ".join(extra))

    if args.edl:
        # EDL 单独跑：验证内置 edlclient 在冻结环境里能不能加载、能不能读分区。
        # 只读，不写设备任何字节。
        attach_console()
        logp, logf = _edl_log_open()
        # 主输出必须是日志文件，不能是控制台。
        # windowed EXE 的 sys.stdout 是 AttachConsole 来的 CONOUT$：在管道里被
        # 重定向、或控制台缓冲区写满时，write 会**阻塞**。而 edl 的每条 print
        # 都夹在 USB 会话中间 —— 一阻塞整条会话就停在那儿，表现为「读分区表读着
        # 读着设备没反应、最后被外部超时杀掉」。实测日志停在 banner，7 分钟无新增。
        sys.stdout = logf
        sys.stderr = logf
        # edlclient 子包里有 `try: from edlclient.X import *` / `except: from X import *`
        # 的写法，只把父目录放进 sys.path 时第一条会失败（冻结环境里 __path__ 布局
        # 不同），于是走到 fallback 后报 No module named 'Library'。把 edlclient
        # 目录本身也加进去，两条路都能通。
        try:
            _here = os.path.dirname(os.path.abspath(__file__))
        except NameError:
            _here = os.getcwd()
        _ec = os.path.join(_here, "edlclient")
        for _p in (_here, _ec):
            if os.path.isdir(_p) and _p not in sys.path:
                sys.path.insert(0, _p)
        import edlman
        print("# EDL %s  %s" % (args.edl, time.strftime("%Y-%m-%d %H:%M:%S")))
        print("# 日志: %s" % logp)
        argv = ["edlman", args.edl] + list(extra)
        if args.serial:
            argv += ["--serial", args.serial]
        old = sys.argv
        sys.argv = argv
        rc = 0
        try:
            rc = edlman._cli()
        except SystemExit:
            raise
        except BaseException as e:
            import traceback
            print("[X] %s: %s" % (type(e).__name__, e))
            traceback.print_exc(file=logf)
            rc = 1
        finally:
            sys.argv = old
            try:
                logf.flush()
            except Exception:
                pass
        _echo_log(logp)
        try:
            logf.close()
        except Exception:
            pass
        return rc

    if args.check or args.root or args.auto or args.gplay:
        attach_console()
        return cli_main(args)
    return gui_main(args.port)


if __name__ == "__main__":
    sys.exit(main())
