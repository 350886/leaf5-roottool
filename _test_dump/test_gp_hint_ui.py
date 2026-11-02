# -*- coding: utf-8 -*-
"""
GUI 冒烟：「装 Google Play」按钮下面那行前置条件说明。

  "C:/Users/<用户>/AppData/Local/Programs/Python/Python312/python.exe" \
      _test_dump/test_gp_hint_ui.py

验四件事：
  1. 集成版（GP_ENABLED=True）时说明存在，文案对
  2. 位置在按钮正下方（y 坐标比较，不是靠人眼看）
  3. 说明不宽于按钮右侧的空间（不会把「谷歌服务？」那行挤换行）
  4. 普通版（GP_ENABLED=False）时按钮与说明都不建 —— 点了只会报错的入口不留

窗口 withdraw 后再构建，不显示、不抢焦点。
"""
import os
import sys
import tkinter as tk
from tkinter import ttk

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


def build(enabled):
    """窗口放到屏幕外再渲染：withdraw 的窗口不做几何布局，winfo_y() 全是 0。"""
    R.GP_ENABLED = enabled
    # __init__ 会 after(300, boot) 去连 adb；destroy 之后再触发会打一串
    # "invalid command name ...boot"，污染输出，这里先打桩。
    R.App.boot = lambda self: None
    root = tk.Tk()
    root.geometry("+4000+4000")
    try:
        ttk.Style().theme_use("clam")
    except Exception:
        pass
    app = R.App(root, port=5057)
    root.update_idletasks()
    root.update()
    return root, app


print("[1] 集成版：说明必须存在")
root, app = build(True)
try:
    hint = getattr(app, "lbl_gplay_hint", None)
    chk(hint is not None, "lbl_gplay_hint 已创建")
    chk(app.btn_gplay is not None, "btn_gplay 已创建")

    text = hint.cget("text") if hint else ""
    print("      文案：%r" % text)
    chk("Google" in text, "含 Google")
    chk("账号" in text, "含「账号」")
    chk("验证通过" in text, "含「验证通过」")
    chk("设置" in text, "指明是在「设备设置」里做")

    print("[2] 位置：按钮下方")
    # 两者父容器不同（按钮在 row4 里、说明在 opt4 里），要比较屏幕绝对坐标
    by, bh = app.btn_gplay.winfo_rooty(), app.btn_gplay.winfo_height()
    hy = hint.winfo_rooty()
    same_parent = hint.master is app.btn_gplay.master
    print("      同一父容器=%s  按钮 rooty=%d h=%d → 底 %d；说明 rooty=%d"
          % (same_parent, by, bh, by + bh, hy))
    # 布局改过两次：最早说明直接挂在 opt4 上（跟按钮不同容器，比 rooty 就行）；
    # 现在按钮和说明一起装进 _btn_group 的定宽盒子，两者同容器纵向堆叠 ——
    # 这时「横排到右边」和「在下方」的区别靠 pack 顺序 + y 坐标判，不能只看容器。
    if same_parent:
        chk(hy >= by + bh, "说明的 y 在按钮下沿之下")
        order = hint.master.pack_slaves()
        chk(order.index(app.btn_gplay) < order.index(hint),
            "按钮排在说明之前（纵向堆叠，不是横排）")
    else:
        chk(hy >= by + bh, "说明的 y 在按钮那一行下沿之下")
        order = hint.master.pack_slaves()
        row = app.btn_gplay.master
        chk(row in order and hint in order, "两者同为 opt4 的子控件")
        chk(order.index(row) < order.index(hint), "按钮那一行排在说明之前")

    print("[3] 尺寸：不挤压同一行")
    bw = app.btn_gplay.winfo_x() + app.btn_gplay.winfo_width()
    hw = hint.winfo_reqwidth()
    print("      按钮右沿 x=%d；说明所需宽 %d" % (bw, hw))
    chk(hw > 0, "宽度撑开了（不是被压成 0）")
    chk(hw < 420, "宽度 < 420（900 宽的窗口里放得下）")

    print("[4] 运行状态标签没被挤掉")
    chk(app.lbl_gplay is not None, "lbl_gplay 仍在")
    chk(app.lbl_gplay.cget("text") == "", "初始为空（等 probe 填）")
finally:
    root.destroy()

print("[5] 普通版：按钮与说明都不建")
root, app = build(False)
try:
    chk(app.btn_gplay is None, "btn_gplay 为 None")
    chk(getattr(app, "lbl_gplay_hint", None) is None, "lbl_gplay_hint 为 None")
finally:
    root.destroy()

print("")
print("通过 %d / 失败 %d" % (OK, FAIL))
sys.exit(1 if FAIL else 0)
