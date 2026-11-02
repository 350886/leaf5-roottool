"""fastbootd 通路（V1 版）：绕开被厂商裁掉 flash 的 abl。

为什么这条路成立
----------------
`fastboot flash` 在 bootloader 模式下由 abl 的命令分发表处理。ONYX 把这条
handler 删了，所以刷任何分区都回 `remote: 'unknown command'` —— 实测 Leaf5
与 Tab 系都一样。但 fastbootd 是跑在 Android 里的 userspace 守护进程
（system/core/fastbootd + libfastboot），写入走
`OpenPartition -> write(blockdev)`，根本不经过 abl 的分发表 ——
abl 只负责把它拉起来，那是 `reboot fastboot`（另一条 handler）。

另一条依据：动态分区（super）设备必然带 fastbootd。system / product /
vendor 这些逻辑分区在 bootloader 里根本不存在，只能由 fastbootd 解开 super
再写。ONYX 4.2 是 Android 13 + 动态分区，所以 fastbootd 一定在。

判定不靠猜：唯一可靠的标志是 `fastboot getvar is-userspace` 返回 yes。
bootloader 模式给 no（或空），fastbootd 给 yes。product 名两边会重样，
不能拿来判。

什么时候用
----------
有 su 就别用这条 —— dd 更快、不重启、写完立刻能回读校验。这条只在
「有镜像但没 root」时才有意义，也就是 V1 里唯一还能写 boot 的轻量通路
（另一条是 9008 EDL，要黑屏重启 3-6 分钟）。
"""

from __future__ import annotations

import os
import re
import subprocess
import time

CREATE_NO_WINDOW = 0x08000000

USERSPACE_YES = ("yes", "true", "1")

# `adb reboot fastboot` 是 Android 10 起的写法，更早的叫 fastbootd。
ADB_ENTER_TARGETS = ("fastboot", "fastbootd")


class FastbootError(Exception):
    pass


def _one(text, n=200):
    """多行输出压成一行 —— 报错只需要里面那句真正的错。"""
    for line in (text or "").splitlines():
        line = line.strip()
        if line:
            return line[:n]
    return "（无输出）"


class Fastboot:
    """fastboot.exe 的薄封装。只做这条通路要用的五件事。"""

    def __init__(self, exe, serial=None, log=None):
        self.exe = exe
        self.serial = serial
        self.log = log or (lambda s: None)

    def available(self):
        return bool(self.exe) and os.path.isfile(self.exe)

    def _argv(self, args):
        cmd = [self.exe]
        if self.serial:
            cmd += ["-s", self.serial]
        return cmd + [str(a) for a in args]

    def run(self, *args, timeout=60):
        if not self.available():
            raise FastbootError("找不到 fastboot.exe：%s" % self.exe)
        try:
            p = subprocess.run(
                self._argv(args),
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=timeout, creationflags=CREATE_NO_WINDOW)
        except subprocess.TimeoutExpired:
            return -1, "", "超时（%d 秒）" % timeout
        out = p.stdout.decode("utf-8", "replace")
        err = p.stderr.decode("utf-8", "replace")
        return p.returncode, out, err

    def devices(self):
        rc, out, err = self.run("devices", timeout=20)
        if rc != 0:
            raise FastbootError("fastboot devices 失败：%s" % _one(err or out))
        found = []
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[1].startswith("fastboot"):
                found.append(parts[0])
        return found

    def getvar(self, name):
        """fastboot 把 getvar 的结果写 stderr，而且带 (bootloader) 前缀。"""
        try:
            rc, out, err = self.run("getvar", name, timeout=20)
        except FastbootError:
            return ""
        m = re.search(r"%s:\s*(\S+)" % re.escape(name), out + "\n" + err)
        return m.group(1) if m else ""

    def flash(self, part, image, timeout=600):
        return self.run("flash", part, image, timeout=timeout)

    def reboot(self, target=""):
        return self.run("reboot", *([target] if target else []), timeout=30)


class Fastbootd:
    """fastbootd 的操作面：进、刷、退。"""

    def __init__(self, adb, fb, log=None):
        self.adb = adb
        self.fb = fb
        self.log = log or (lambda s: None)

    # ---------------- 状态 ----------------
    def devices(self):
        try:
            return self.fb.devices()
        except FastbootError:
            return []

    def is_userspace(self):
        try:
            v = (self.fb.getvar("is-userspace") or "").strip().lower()
        except FastbootError:
            return False
        return v in USERSPACE_YES

    def mode(self):
        """'fastbootd' / 'bootloader' / 'none'。"""
        if not self.devices():
            return "none"
        return "fastbootd" if self.is_userspace() else "bootloader"

    def partition_size(self, part):
        """fastbootd 只读得到分区容量，读不到内容 —— 这是它唯一的校验手段。"""
        raw = (self.fb.getvar("partition-size:" + part) or "").strip()
        if not raw:
            return 0
        try:
            return int(raw) if raw.isdigit() else int(raw, 16)
        except ValueError:
            return 0

    # ---------------- 进去 ----------------
    def _wait(self, seconds, poll=1.5):
        """等 fastbootd 上线。只认 is-userspace=yes，不等 bootloader。"""
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            if self.devices() and self.is_userspace():
                return True
            time.sleep(max(0.2, poll))
        return False

    def enter(self, seconds=90):
        """把设备弄进 fastbootd。返回 (成功, 怎么进去的 / 为什么不行)。"""
        m = self.mode()
        if m == "fastbootd":
            return True, "已经在 fastbootd（is-userspace=yes）"

        # 1) 已在 bootloader：让 bootloader 自己切。
        #    `reboot fastboot` 和 `flash` 是两条 handler，裁后者不影响前者。
        if m == "bootloader":
            self.log("  设备在 bootloader，切 fastbootd…")
            rc, out, err = self.fb.reboot("fastboot")
            if rc != 0:
                return False, ("bootloader 拒绝 `reboot fastboot`：%s"
                               % _one(err or out))
            if self._wait(seconds):
                return True, "bootloader → `reboot fastboot`"
            return False, ("发了 `reboot fastboot` 但 %d 秒内没等到 "
                           "is-userspace=yes（设备可能没有 fastbootd，"
                           "或在重启途中掉线）" % seconds)

        # 2) 没有 fastboot 设备：看 adb。这是主路 —— 工具通常在系统里
        #    就对 adb 有连接，一条 reboot 比让用户手按音量键靠谱。
        try:
            devs = self.adb.devices()
        except Exception:
            devs = []
        if not devs:
            return False, "adb 与 fastboot 都没有设备；插 USB 并确认「USB 调试」已开"

        try:
            dyn = (self.adb.getprop("ro.boot.dynamic_partitions") or "").strip()
        except Exception:
            dyn = ""
        if dyn and dyn not in ("true", "1"):
            self.log("  ro.boot.dynamic_partitions=%s，fastbootd 可能不存在，仍然试一次"
                     % dyn)

        last = ""
        for target in ADB_ENTER_TARGETS:
            self.log("  adb reboot %s" % target)
            try:
                rc, out, err = self.adb.run(["reboot", target], timeout=20)
            except Exception as e:
                last = "adb reboot %s 失败：%s" % (target, e)
                continue
            if rc != 0:
                last = "adb reboot %s 失败：%s" % (target, _one(err or out))
                continue
            if self._wait(seconds):
                return True, "adb reboot %s" % target
            last = ("adb reboot %s 之后 %d 秒内 fastboot 没报 is-userspace=yes"
                    % (target, seconds))
        return False, last

    # ---------------- 刷 ----------------
    def flash(self, part, image, timeout=600):
        """刷一个分区，返回 (ok, 输出, 真正用的分区名)。

        分区名回退：fastbootd 报 unknown partition 时去掉 _a/_b 再试一次。
        boot 是物理分区，理论上带后缀，但不同引擎实现不一致 ——
        比让整条通路在这里断掉强。
        """
        if self.mode() != "fastbootd":
            raise FastbootError(
                "当前不是 fastbootd（is-userspace≠yes），拒绝 flash")
        rc, out, err = self.fb.flash(part, image, timeout=timeout)
        text = (out + "\n" + err).strip()
        if rc == 0:
            return True, text, part

        low = text.lower()
        if "_" in part and ("unknown partition" in low or "not found" in low):
            alt = part.rsplit("_", 1)[0]
            self.log("  fastbootd 不认识 %s，改试 %s" % (part, alt))
            rc2, out2, err2 = self.fb.flash(alt, image, timeout=timeout)
            text2 = (out2 + "\n" + err2).strip()
            if rc2 == 0:
                return True, text2, alt
            return False, text2, part
        return False, text, part

    def reboot(self, target=""):
        rc, out, err = self.fb.reboot(target)
        if rc != 0:
            try:
                self.adb.run(["reboot"] + ([target] if target else []), timeout=20)
                return True, "adb reboot"
            except Exception:
                return False, _one(err or out)
        return True, "fastboot reboot"
