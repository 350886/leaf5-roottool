# -*- coding: utf-8 -*-
"""GUI 载荷状态冒烟：三种状态（bundled / targets_only / none）下
主按钮主次、状态栏文案是否按预期切换。

  python _test_dump/test_payload_state.py

不显示窗口（withdraw），只断言控件属性。
"""
import os
import sys
import tkinter as tk
from tkinter import ttk

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import roottool as R


def main():
    root = tk.Tk()
    root.withdraw()
    try:
        ttk.Style().theme_use("clam")
    except Exception:
        pass

    app = R.App(root, port=5056)
    root.update_idletasks()

    ok = True

    def chk(cond, msg):
        nonlocal ok
        print(("  [ok] " if cond else "  [XX] ") + msg)
        ok = ok and bool(cond)

    # --- 1. none：包内无 .so、targets 也空 → 向导必须是主按钮
    print("1) none")
    app._apply_payload_state("none", 0)
    chk("首次必做" in app.btn_adapter.cget("text"), "向导按钮文案带「首次必做」")
    chk(app.btn_adapter.cget("bg") == R.ACCENT, "向导按钮是主色（ACCENT）")
    chk(app.btn_one.cget("bg") == R.BG3, "一键全自动降为普通样式")
    chk(app.btn_one.cget("state") != "disabled", "一键没被禁用（仍可自己硬闯）")
    chk("未内置载荷" in app.lbl_status.cget("text"), "状态栏提示未内置载荷")
    chk(app.lbl_status.cget("fg") == R.WARN_C, "状态栏用 warn 色")

    # --- 2. targets_only：包内无，但适配目录里有 → 一键可用
    print("2) targets_only")
    app._apply_payload_state("targets_only", 2)
    chk(app.btn_adapter.cget("text") == "内核适配向导", "向导按钮恢复常规模样")
    chk(app.btn_one.cget("bg") == R.ACCENT, "一键全自动回到主色")
    chk("适配目录" in app.lbl_status.cget("text"), "状态栏说明载荷来自适配目录")
    chk(app.lbl_status.cget("fg") == R.OK_C, "状态栏用 ok 色")

    # --- 3. bundled：包内有 → 一键为主
    print("3) bundled")
    app.lbl_status.configure(text="sentinel")
    app._apply_payload_state("bundled", 0)
    chk(app.btn_one.cget("bg") == R.ACCENT, "一键全自动是主色")
    chk(app.btn_adapter.cget("bg") == R.BG3, "向导是普通样式")
    chk(app.lbl_status.cget("text") == "sentinel", "bundled 不覆盖已有状态栏")

    # --- 4. refresh_targets 的判定分支：patch 掉探测源
    print("4) refresh_targets 判定")
    real_rp = R.resource_path
    import adapter
    real_lt = adapter.list_targets
    try:
        R.resource_path = lambda *a: os.path.join("Z:/definitely_not_here", *a)
        adapter.list_targets = lambda: []
        app.refresh_targets()
        chk(app._payload_state == "none", "包内无 + targets 空 → none")

        adapter.list_targets = lambda: [{"id": "x", "dir": "Z:/x"}]
        app.refresh_targets()
        chk(app._payload_state == "targets_only", "包内无 + targets 有 → targets_only")

        R.resource_path = real_rp
        app.refresh_targets()
        want = "bundled" if os.path.isfile(real_rp("assets", "payload", "preload.so")) \
            else "targets_only"
        chk(app._payload_state == want, f"恢复真实环境 → {want}")
        chk("已装 1 份适配载荷" in app.lbl_targets.cget("text")
            or "还没有适配载荷" in app.lbl_targets.cget("text"),
            "targets 计数文案正常")
    finally:
        R.resource_path = real_rp
        adapter.list_targets = real_lt

    root.destroy()
    print("\n结果:", "全部通过" if ok else "有失败项")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
