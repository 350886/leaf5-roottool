# -*- coding: utf-8 -*-
"""
GUI 冒烟：窗口 withdraw 后构建，只验控件能建起来、文案对不对，不显示窗口。

  python _test_dump/test_gui.py

要用带 tkinter 的那个解释器跑（微软商店精简版没有）。
"""
import os
import sys
import tkinter as tk
from tkinter import ttk

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import roottool as R


def walk(w):
    for c in w.winfo_children():
        yield c
        yield from walk(c)


def main():
    root = tk.Tk()
    # 先 withdraw：不显示窗口，不抢焦点，测完直接 destroy
    root.withdraw()
    st = ttk.Style()
    try:
        st.theme_use("clam")
    except Exception:
        pass

    app = R.App(root, port=5055)
    root.update_idletasks()

    ok = True

    # 1. 底栏必须写清适用型号
    foot = app.lbl_foot.cget("text")
    print("footer :", foot)
    for token in (R.TARGET_MODEL, R.TARGET_FIRMWARE, R.TARGET_KERNEL):
        if token not in foot:
            print(f"  [!] 底栏缺 {token}")
            ok = False

    # 2. 放行开关存在且默认不勾
    print("var_force 默认 :", app.var_force.get())
    if app.var_force.get():
        print("  [!] 默认不该勾上")
        ok = False

    # 3. 控件文案
    texts = [c.cget("text") for c in walk(root)
             if isinstance(c, tk.Checkbutton) and c.cget("text")]
    print("勾选项 :", texts)
    if not any("跳过型号核对" in t for t in texts):
        print("  [!] 找不到「跳过型号核对」")
        ok = False

    # 4. 勾上之后 _make_worker 要把它透传成 force_model
    app.var_force.set(True)
    app.adb = type("FakeAdb", (), {"port": 5055, "serial": "X", "env": {},
                                   "kill_server": lambda self: None,
                                   "start_server": lambda self: None})()
    app._selected_serial = lambda: "X"
    w = app._make_worker(do_detect=True, do_deploy=True, tries=1)
    print("worker.force_model :", w.force_model)
    if not w.force_model:
        print("  [!] 勾了但没透传")
        ok = False

    # 5. 取消勾选再建一个，必须是 False
    app.var_force.set(False)
    w2 = app._make_worker(do_detect=True, do_deploy=True, tries=1)
    print("再建一个 force_model :", w2.force_model)
    if w2.force_model:
        print("  [!] 没勾却是 True")
        ok = False

    root.destroy()
    print()
    print("GUI 冒烟", "通过" if ok else "失败")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
