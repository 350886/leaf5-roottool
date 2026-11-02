"""每个按钮 / 每个选项下面都必须有「用在什么情况」那一行。

只测文案存在性不够 —— 说明写在一个没人会滚到的地方等于没写。
这里直接量控件树：按钮或勾选框的**父容器里**，紧跟其后必须有一个
文本以「用在·」开头的 Label，且它在 pack 顺序上排在控件之后。

    "C:/Users/thelu/AppData/Local/Programs/Python/Python312/python.exe" ^
        E:\\BOOX\\root-tool\\_test_dump\\test_hints_ui.py
"""
import sys
import tkinter as tk
from tkinter import ttk

sys.path.insert(0, r"E:\BOOX\root-tool")

import roottool as R                # noqa: E402

R.GP_ENABLED = True                 # 集成版才有 Google Play 那一组，要一起验
R.App.boot = lambda self: None      # 不自动连 adb

FAIL = []


def chk(ok, msg):
    print("  [%s] %s" % ("ok" if ok else "XX", msg))
    if not ok:
        FAIL.append(msg)


def hint_of(widget):
    """同容器里，pack 顺序在 widget 之后、文本以「用在·」开头的第一个 Label。"""
    try:
        sibs = widget.master.pack_slaves()
    except Exception:
        return None
    if widget not in sibs:
        return None
    for w in sibs[sibs.index(widget) + 1:]:
        if isinstance(w, tk.Label):
            txt = str(w.cget("text"))
            if txt.startswith("用在·"):
                return txt
    return None


def walk(w, out):
    for c in w.winfo_children():
        out.append(c)
        walk(c, out)


def main():
    root = tk.Tk()
    root.geometry("900x880+2000+2000")   # 摆到屏幕外，避免闪窗
    try:
        ttk.Style().theme_use("clam")
    except Exception:
        pass
    app = R.App(root, port=5059)
    root.update_idletasks()

    all_w = []
    walk(root, all_w)

    # _btn 建的是 tk.Button（自绘扁平样式），不是 ttk.Button
    btns = [w for w in all_w if isinstance(w, tk.Button)]
    chks = [w for w in all_w if isinstance(w, tk.Checkbutton)]

    print("[1] 按钮：共 %d 个，每个都要有「用在·」" % len(btns))
    for b in btns:
        txt = str(b.cget("text"))
        h = hint_of(b)
        chk(h is not None, "按钮「%s」下方有使用条件%s"
            % (txt, "" if h is None else "：" + h))

    print("[2] 选项：共 %d 个，每个都要有「用在·」" % len(chks))
    for c in chks:
        txt = str(c.cget("text"))
        h = hint_of(c)
        chk(h is not None, "选项「%s」下方有使用条件%s"
            % (txt, "" if h is None else "：" + h))

    print("[3] 条件文案不是空壳")
    all_hints = [str(w.cget("text")) for w in all_w
                 if isinstance(w, tk.Label)
                 and str(w.cget("text")).startswith("用在·")]
    chk(len(all_hints) >= len(btns) + len(chks) - 1,
        "条件行数 %d ≥ 控件数 %d（允许 AMS 那种跟随勾选框的一处差异）"
        % (len(all_hints), len(btns) + len(chks)))
    short = [h for h in all_hints if len(h) <= len("用在·") + 2]
    chk(not short, "没有只写「用在」不写内容的空行（%d 条）" % len(short))

    print("[4] 说明没被容器裁掉")
    # box 是 pack_propagate(False) 的定宽定高容器，说明超出高度会被切。
    # 判据：Label 的 reqheight 之和不能超过所在 box 的高度。
    bad = []
    for w in all_w:
        if not isinstance(w, tk.Label):
            continue
        if not str(w.cget("text")).startswith("用在·"):
            continue
        box = w.master
        if not box.winfo_ismapped():
            continue
        need = (w.winfo_rooty() - box.winfo_rooty()) + w.winfo_reqheight()
        if need > box.winfo_height() + 1:
            bad.append("%s 需 %d > 容器 %d" % (str(w.cget("text"))[:12],
                                              need, box.winfo_height()))
    chk(not bad, "所有条件行都在容器高度内 %s" % ("" if not bad else bad))

    root.destroy()
    print()
    if FAIL:
        print("通过 %d / 失败 %d" % (0, len(FAIL)))
        for f in FAIL:
            print("  XX", f)
        return 1
    print("全部通过")
    return 0


if __name__ == "__main__":
    sys.exit(main())
