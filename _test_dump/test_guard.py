# -*- coding: utf-8 -*-
"""
guard 闸门的离线自测：不接设备，用假 adb 跑 stage_detect + guard 全流程。

  E:/BOOX/edl-venv/Scripts/python.exe _test_dump/test_guard.py
"""
import os
import queue
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import roottool as R


class FakeAdb:
    """只实现 stage_detect 用到的那几个方法。"""
    port = 5055
    serial = "MOCK0001"
    exe = "adb.exe"
    env = {}

    def __init__(self, model="Leaf5", krel="4.19.157-perf-g77c132eccfab-dirty #38"):
        self._model = model
        self._krel = krel
        self.props = {
            "ro.product.model": model,
            "ro.product.brand": "ONYX",
            "ro.build.version.release": "13",
            "ro.build.version.sdk": "33",
            "ro.build.display.id": "2024-09-28",
            "ro.build.fingerprint": "ONYX/Leaf5x/Leaf5:13/TQ3A/x0928:user/release-keys",
            "sys.boot_completed": "1",
        }

    def devices(self):
        return [{"serial": self.serial, "state": "device", "model": self._model}]

    def getprop(self, k):
        return self.props.get(k, "")

    def shell(self, cmd, timeout=None):
        if "uname -r" in cmd:
            return self._krel
        return ""

    def uptime(self):
        return 12345

    def getenforce(self):
        return "Enforcing"

    def run(self, args, timeout=None):
        # su -c id 探测：模拟"还没 root"
        return (1, "", "")


def run_case(name, model, krel, do_deploy=True, force=False, expect_block=True):
    q = queue.Queue()
    w = R.RootWorker(FakeAdb(model, krel), q=q, do_detect=True,
                     do_deploy=do_deploy, force_model=force)
    w.stage_detect()
    lines = []
    while True:
        try:
            item = q.get_nowait()
        except queue.Empty:
            break
        lines.append(str(item[1]) if len(item) > 1 else "")

    blocked = False
    try:
        w.guard()
    except R.ModelMismatch:
        blocked = True

    # guard 里打印的内容也要收
    while True:
        try:
            item = q.get_nowait()
        except queue.Empty:
            break
        lines.append(str(item[1]) if len(item) > 1 else "")

    ok = (blocked == expect_block)
    print(f"[{'OK ' if ok else 'FAIL'}] {name}")
    print(f"        blockers={w.blockers}  blocked={blocked}  expect={expect_block}")
    if blocked:
        for ln in lines:
            if "已停止" in ln or "·" in ln or "只对" in ln:
                print("        | " + ln)
    return ok


def main():
    cases = [
        ("原厂 Leaf5 / 4.19.157  → 放行", "Leaf5", "4.19.157-perf-g77c132eccfab-dirty #38", True, False, False),
        ("换成 Tab10 型号        → 拦", "Tab10", "4.19.157-perf-xxx #38", True, False, True),
        ("内核换成 5.15          → 拦", "Leaf5", "5.15.94-android13 #1", True, False, True),
        ("型号对但内核新          → 拦", "Leaf5", "4.19.200-perf #12", True, False, True),
        ("Tab10 + force-model    → 放行", "Tab10", "5.15.94 #1", True, True, False),
        ("Tab10 但只检测(不部署)  → 放行", "Tab10", "5.15.94 #1", False, False, False),
        ("读不到型号/内核         → 放行", "", "", True, False, False),
    ]
    results = [run_case(*c) for c in cases]
    print()
    print(f"{sum(results)}/{len(results)} 通过")
    return 0 if all(results) else 1


if __name__ == "__main__":
    sys.exit(main())
