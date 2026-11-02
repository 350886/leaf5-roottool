# -*- coding: utf-8 -*-
"""
--sysadmin 判定：与 V2 的 ExploitOps.verdict() 对齐。

  python _test_dump/test_sysadmin.py

旧行为是「route 日志里读不到 bnd= 就放行」—— 确认不了能力却说通过，
下一步 mount 只读分区就靠运气。现在改成：读不到 = 判失败。

不连设备、不写任何文件：adb 全部打桩，只喂 judge() 需要的四段输出。
"""
import os
import queue
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import roottool as R

OK = 0
FAIL = 0


def chk(cond, msg):
    global OK, FAIL
    if cond:
        OK += 1
        print("  [ok] " + msg)
    else:
        FAIL += 1
        print("  [XX] " + msg)


class FakeAdb:
    """judge() 只读四样东西：uptime / exec_probe 的 CapEff / su -c id / route 日志里的 bnd=。"""

    def __init__(self, up=1000, capeff="000001ffffffffff",
                 idline="uid=0(root) gid=0(root)", raw=""):
        self.up = up
        # exec_probe.txt 里是两列（"CapEff:\t<hex>"），judge() 取 split()[1]
        self.capeff_line = ("CapEff:\t" + capeff) if capeff else ""
        self.idline = idline
        self.raw = raw

    def uptime(self):
        return self.up

    def shell(self, cmd, timeout=None):
        if "'^CapEff'" in cmd:
            return self.capeff_line
        if '-c "id"' in cmd:
            return self.idline
        if "round 3 caps" in cmd:
            return self.raw
        return ""


def worker(adb, require_sysadmin):
    """不走 __init__（那会连设备），只拿到能调 judge() 的壳。"""
    w = R.RootWorker.__new__(R.RootWorker)
    w.adb = adb
    w.require_sysadmin = require_sysadmin
    w.log = lambda *a, **k: None
    return w


BND_FULL = "000001ffffffffff"          # bit21 = 1
BND_NO_SYSADMIN = "000001ffffdfffff"   # 0xffdfffff = 0xffffffff 清掉 0x200000（bit21）
RUNLOG = "/data/local/tmp/runs/t.log"


def raw_with(bnd):
    return "round 3 caps ok pid=1234 bnd=%s inh=0000000000000000" % bnd


# ---------------- 1. 常量 ----------------
print("[1] 常量")
chk(R.CAP_SYS_ADMIN == 21, "CAP_SYS_ADMIN == 21（linux/capability.h）")
chk((1 << R.CAP_SYS_ADMIN) == 0x200000, "1<<21 == 0x200000")

# ---------------- 2. 有 bit21 就通过 ----------------
print("[2] bnd 带 CAP_SYS_ADMIN")
w = worker(FakeAdb(raw=raw_with(BND_FULL)), True)
ok, info = w.judge(RUNLOG, 1000)
chk(ok, "ok=True")
chk(info["bnd"] == BND_FULL, "info 里带回 bnd 原值")
chk(info.get("reason") is None, "没有 reason")

# ---------------- 3. bnd 里没有 bit21 ----------------
print("[3] bnd 缺 bit21")
w = worker(FakeAdb(raw=raw_with(BND_NO_SYSADMIN)), True)
ok, info = w.judge(RUNLOG, 1000)
chk(not ok, "ok=False")
chk("不在 bnd 里" in info["reason"], "reason 说明不在 bnd 里")
chk("bnd=0x" in info["reason"], "reason 带上实际值：%s" % info["reason"])
chk("mount" in info["reason"], "reason 说清后果（mount / 改只读挂载）")

# ---------------- 4. bnd 读不到（本次要改的那条）----------------
print("[4] route 日志里没有 bnd= → 判失败")
w = worker(FakeAdb(raw="round 3 caps ok pid=1234"), True)
ok, info = w.judge(RUNLOG, 1000)
chk(not ok, "ok=False（旧版这里会放行）")
chk("读不到 bnd=" in info["reason"], "reason：%s" % info["reason"])

print("[4b] 整份日志是空的")
w = worker(FakeAdb(raw=""), True)
ok, info = w.judge(RUNLOG, 1000)
chk(not ok, "ok=False")
chk("读不到 bnd=" in info["reason"], "reason 同上")

print("[4c] bnd 不是合法十六进制")
w = worker(FakeAdb(raw="round 3 caps ok bnd=zzzz"), True)
ok, info = w.judge(RUNLOG, 1000)
chk(not ok, "ok=False")
chk("读不到 bnd=" in info["reason"], "正则匹配不到 = 读不到，不抛 ValueError 冒到上层")

# ---------------- 5. bnd=0 不能被当成「读不到」----------------
print("[5] bnd=0（值存在但全 0）")
w = worker(FakeAdb(raw=raw_with("0")), True)
ok, info = w.judge(RUNLOG, 1000)
chk(not ok, "ok=False")
chk("不在 bnd 里" in info["reason"],
    "走「不在 bnd 里」分支，不是「读不到」：%s" % info["reason"])
chk("bnd=0x0" in info["reason"], "reason 显示 0x0")

# ---------------- 6. 没开 --sysadmin 就不管 bnd ----------------
print("[6] require_sysadmin=False")
w = worker(FakeAdb(raw="round 3 caps ok pid=1"), False)
ok, info = w.judge(RUNLOG, 1000)
chk(ok, "bnd 缺失也通过（这个开关只影响开着的场景）")

w = worker(FakeAdb(raw=raw_with(BND_NO_SYSADMIN)), False)
ok, _ = w.judge(RUNLOG, 1000)
chk(ok, "bnd 缺 bit21 也通过")

# ---------------- 7. 其他失败原因不受影响 ----------------
print("[7] 前置条件仍按原顺序判")
w = worker(FakeAdb(capeff="00000000000000c0", raw=raw_with(BND_FULL)), True)
ok, info = w.judge(RUNLOG, 1000)
chk(not ok, "CapEff=0xc0 → 失败")
chk("能力没抬起来" in info["reason"], "reason 指向 CapEff，不是 sysadmin")

w = worker(FakeAdb(capeff="", raw=raw_with(BND_FULL)), True)
ok, info = w.judge(RUNLOG, 1000)
chk(not ok, "没有 exec_probe.txt → 失败")
chk("exec_probe" in info["reason"], "reason：%s" % info["reason"])

w = worker(FakeAdb(idline="uid=2000(shell)", raw=raw_with(BND_FULL)), True)
ok, info = w.judge(RUNLOG, 1000)
chk(not ok, "uid=2000 → 失败")
chk("uid 没到 0" in info["reason"], "reason：%s" % info["reason"])

w = worker(FakeAdb(up=10, raw=raw_with(BND_FULL)), True)
ok, info = w.judge(RUNLOG, 1000)
chk(not ok, "uptime 回绕（panic 重启）→ 失败")
chk("回绕" in info["reason"], "reason：%s" % info["reason"])

# ---------------- 8. 大写十六进制 ----------------
print("[8] 大写 hex 也能解")
w = worker(FakeAdb(raw=raw_with("000001FFFFFFFFFF")), True)
ok, info = w.judge(RUNLOG, 1000)
chk(ok, "ok=True")
chk(int(info["bnd"], 16) >> 21 & 1 == 1, "大写串解析出来的 bit21 = 1")

# ---------------- 9. 构造与 CLI 的传参 ----------------
print("[9] require_sysadmin 一路传到底")
w = R.RootWorker(None, tries=1, require_sysadmin=True, q=queue.Queue())
chk(w.require_sysadmin is True, "RootWorker(require_sysadmin=True) 存住了")
w = R.RootWorker(None, tries=1, require_sysadmin=False, q=queue.Queue())
chk(w.require_sysadmin is False, "默认 False")

# ---------------- 10. 和 V2 的文案对齐 ----------------
print("[10] 与 V2 verdict() 的措辞一致")
w = worker(FakeAdb(raw=""), True)
_, info = w.judge(RUNLOG, 1000)
chk(info["reason"] == "有 uid=0，但日志里读不到 bnd=，无法确认 CAP_SYS_ADMIN",
    "读不到时的文案逐字一致")

w = worker(FakeAdb(raw=raw_with(BND_NO_SYSADMIN)), True)
_, info = w.judge(RUNLOG, 1000)
v2_head = "有 uid=0，但 CAP_SYS_ADMIN 不在 bnd 里（bnd=0x"
chk(info["reason"].startswith(v2_head), "缺 bit21 时沿用 V2 的开头")


print("")
print("通过 %d / 失败 %d" % (OK, FAIL))
sys.exit(1 if FAIL else 0)
