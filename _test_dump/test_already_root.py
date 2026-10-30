# -*- coding: utf-8 -*-
"""
已 root 拦截冒烟：设备上已经有 su 时不该再推载荷、跑 exploit。

  python _test_dump/test_already_root.py

两段：
  A. RootWorker 的分支（stage_* 全部打桩，只看 run() 的走向）
  B. App._on_done 的分发（窗口 withdraw，弹窗打桩）

不连设备、不写任何文件。
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


class StubWorker(R.RootWorker):
    """把会碰设备的阶段全部替换成记账，只看 run() 走哪条路。"""

    def __init__(self, root_label=None, su_src=None, ver=None, **kw):
        kw.setdefault("q", queue.Queue())
        super().__init__(None, **kw)
        self._stub_root_label = root_label
        self._stub_su = su_src
        self._stub_ver = ver
        self.calls = []

    def stage_detect(self):
        self.calls.append("detect")
        self.already_root = self._stub_root_label
        self.su_src = self._stub_su
        self.magisk_ver = self._stub_ver
        return True

    def guard(self):
        self.calls.append("guard")

    def stage_adapt(self):
        self.calls.append("adapt")

    def stage_deploy(self):
        self.calls.append("deploy")

    def stage_root(self, base=0.0, span=1.0):
        self.calls.append("root")
        return True, {"capeff": "test"}

    def stage_verify(self):
        self.calls.append("verify")
        return True

    def stage_magisk(self):
        self.calls.append("magisk")
        return True

    def stage_ams_module_only(self):
        self.calls.append("module")
        return True

    def drain_done(self):
        """run() 是同步调的，done 已经在队列里。"""
        while True:
            try:
                kind, *rest = self.q.get_nowait()
            except queue.Empty:
                return None
            if kind == "done":
                return (bool(rest[0]), rest[1] if len(rest) > 1 else {})


def run_worker(**kw):
    w = StubWorker(**kw)
    w.run()
    return w, w.drain_done()


def main():
    M = dict(root_label="Magisk", su_src="/debug_ramdisk/su", ver="31.1:MAGISK:R")

    # --- 1. 已 root（Magisk）+ 没勾 Magisk/模块 → 拦，且什么都不做
    print("1) Magisk root，未勾任何选项")
    w, done = run_worker(**M, do_deploy=True)
    chk(w.calls == ["detect", "guard"], f"只跑 detect+guard，实际 {w.calls}")
    chk(done and done[0] is False, "done ok=False")
    chk(done and done[1].get("blocked") == "already_root", "blocked=already_root")
    chk(done and "31.1:MAGISK:R" in done[1].get("reason", ""), "reason 带版本串")
    chk(done and done[1].get("su") == "/debug_ramdisk/su", "info 带 su 路径")

    # --- 2. 已 root（Magisk）+ 勾了 Magisk → 也拦（叠补丁风险）
    print("2) Magisk root，勾了「安装 Magisk」")
    w, done = run_worker(**M, do_deploy=True, with_magisk=True)
    chk(w.calls == ["detect", "guard"], f"仍然不动设备，实际 {w.calls}")
    chk(done and done[1].get("blocked") == "already_root", "blocked=already_root")
    chk(done and "叠补丁" in done[1].get("reason", ""), "reason 说明叠补丁风险")

    # --- 3. 已 root（Magisk）+ 只勾模块 → 跳过 exploit，装模块
    print("3) Magisk root，只勾「装 AMS 模块」")
    w, done = run_worker(**M, do_deploy=True, with_module=True)
    chk("root" not in w.calls, f"没跑 exploit，实际 {w.calls}")
    chk("deploy" not in w.calls, "也没推载荷")
    chk("module" in w.calls, "走到了模块阶段")
    chk(done and done[0] is True, "done ok=True")

    # --- 4. 临时 root（exploit 给的）+ 勾 Magisk → 跳过 exploit 直接装
    print("4) 临时 root，勾了「安装 Magisk」")
    w, done = run_worker(root_label="exploit 临时", su_src=R.DEV_SU, ver=None,
                         do_deploy=True, with_magisk=True)
    chk("root" not in w.calls, f"跳过 exploit，实际 {w.calls}")
    chk("magisk" in w.calls, "直接进 Magisk 阶段")
    chk(done and done[0] is True, "done ok=True")

    # --- 5. 临时 root + 什么都没勾 → 拦（提示只能持久化）
    print("5) 临时 root，未勾任何选项")
    w, done = run_worker(root_label="exploit 临时", su_src=R.DEV_SU, ver=None,
                         do_deploy=True)
    chk(w.calls == ["detect", "guard"], f"不动设备，实际 {w.calls}")
    chk(done and "持久化" in done[1].get("reason", ""), "reason 提示怎么持久化")

    # --- 6. force_rerun 放行
    print("6) 已 root + force_rerun")
    w, done = run_worker(**M, do_deploy=True, force_rerun=True)
    chk(w.calls == ["detect", "guard", "adapt", "deploy", "root", "verify"],
        f"按老路径跑完，实际 {w.calls}")
    chk(done and done[0] is True, "done ok=True")

    # --- 7. 没 root → 老路径不变
    print("7) 未 root")
    w, done = run_worker(root_label=None, do_deploy=True)
    chk(w.calls == ["detect", "guard", "adapt", "deploy", "root", "verify"],
        f"老路径不变，实际 {w.calls}")
    chk(done and done[0] is True, "done ok=True")

    # --- 8. 纯检测（do_deploy=False）不许跑到 stage_root
    print("8) 纯检测 do_deploy=False")
    w, done = run_worker(**M, do_deploy=False)
    chk(w.calls == ["detect", "guard"], f"只读，实际 {w.calls}")
    chk(done and done[0] is True, "done ok=True")
    chk(done and done[1].get("detect_only") is True, "info 标 detect_only")
    chk(done and done[1].get("root") == "Magisk", "info 带 root 状态")

    # --- 9. GUI 分发
    print("9) App._on_done 分发")
    try:
        import tkinter as tk
        from tkinter import ttk
    except ImportError:
        print("  [--] 没有 tkinter，跳过 GUI 段")
        return report()

    root = tk.Tk()
    root.withdraw()
    try:
        ttk.Style().theme_use("clam")
    except Exception:
        pass
    app = R.App(root, port=5057)
    root.update_idletasks()

    asked = {"n": 0, "answer": False}
    real_box = R.messagebox

    class FakeBox:
        @staticmethod
        def askyesno(title, msg):
            asked["n"] += 1
            asked["msg"] = msg
            return asked["answer"]

    R.messagebox = FakeBox
    try:
        # 9a. already_root → 绿色状态栏 + 弹窗
        app._on_done(False, {"reason": "设备已经是 Magisk root（31.1:MAGISK:R）",
                             "blocked": "already_root",
                             "su": "/debug_ramdisk/su", "magisk": "31.1:MAGISK:R"})
        chk(asked["n"] == 1, "弹了一次确认框")
        chk("已 root" in app.lbl_status.cget("text"), "状态栏写「已 root」")
        chk(app.lbl_status.cget("fg") == R.OK_C, "用 ok 色，不标红")
        chk(app._force_rerun is False, "选「否」时不置强制重跑")

        # 9b. 选「是」→ 置旗标
        asked["answer"] = True
        app._force_rerun = False
        app.start_one_click = lambda: None      # 别真起 worker
        app._on_done(False, {"reason": "x", "blocked": "already_root",
                             "su": "/debug_ramdisk/su", "magisk": "31.1"})
        chk(app._force_rerun is True, "选「是」置 _force_rerun")

        # 9c. 普通失败仍然是红字
        asked["n"] = 0
        app._on_done(False, {"reason": "跑了 3 轮都没成"})
        chk(app.lbl_status.cget("fg") == R.BAD_C, "普通失败标红")
        chk(asked["n"] == 0, "普通失败不弹已 root 框")

        # 9d. detect_only → 状态栏区分三种情况
        app._on_done(True, {"detect_only": True, "root": "Magisk", "magisk": "31.1:MAGISK:R"})
        chk("Magisk 31.1:MAGISK:R" in app.lbl_status.cget("text"), "检测收尾显示 Magisk 版本")
        app._on_done(True, {"detect_only": True, "root": None, "magisk": None})
        chk("未 root" in app.lbl_status.cget("text"), "检测收尾显示未 root")

        # 9e. 一次性旗标：取一次就清
        app._force_rerun = True
        app._take_force_rerun()
        chk(app._force_rerun is False, "_take_force_rerun 取完即清")
    finally:
        R.messagebox = real_box
        root.destroy()

    return report()


def report():
    print()
    print(f"通过 {OK} / {OK + FAIL}")
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
