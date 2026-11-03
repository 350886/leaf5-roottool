# -*- coding: utf-8 -*-
"""自绘滚动条的冒烟：比例、拖动、点轨道、滚轮、内容不足时的表现。

    "C:/Users/thelu/AppData/Local/Programs/Python/Python312/python.exe" ^
        E:////BOOX////root-tool////_test_dump////test_scroll.py

为什么是直跑脚本：微软商店那个精简版解释器没带 tcl/tk，pytest 收集期就 ImportError。
这个仓库所有碰 tkinter 的测试都是直跑。
"""
import os
import sys
import tkinter as tk

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from thinbar import MIN_THUMB, ThinBar        # noqa: E402

FAIL = []


def chk(ok, msg):
    print("  [%s] %s" % ("ok" if ok else "XX", msg))
    if not ok:
        FAIL.append(msg)


class Ev:
    """假的鼠标事件。只带被测代码用到的字段。"""

    def __init__(self, y=0, num=0, delta=0):
        self.y = y
        self.num = num
        self.delta = delta


def build(root, content_h):
    cv = tk.Canvas(root, width=200, height=300, highlightthickness=0)
    bar = ThinBar(root, command=cv.yview, target=cv)
    cv.configure(yscrollcommand=bar.set)
    bar.pack(side="right", fill="y")
    cv.pack(side="left", fill="both", expand=True)

    inner = tk.Frame(cv, bg="#000")
    cv.create_window((0, 0), window=inner, anchor="nw")
    tk.Frame(inner, width=180, height=content_h, bg="#333").pack()
    inner.update_idletasks()
    cv.configure(scrollregion=cv.bbox("all"))
    return cv, bar


def main():
    root = tk.Tk()
    root.geometry("300x300+2400+2400")   # 摆到屏幕外，不闪窗
    root.update_idletasks()

    # --- 1. 内容一屏装得下：不画滑块 ---
    cv, bar = build(root, 100)
    root.update_idletasks()
    root.update()
    bar.set(*cv.yview())
    root.update_idletasks()
    chk(bar._span == (0, 0), "内容装得下时不画滑块 %s" % (bar._span,))
    chk(bar._last - bar._first > 0.999, "内容装得下时 first/last 是满的")

    # --- 2. 内容超出：滑块按比例 ---
    cv.destroy()
    bar.destroy()
    cv, bar = build(root, 900)
    root.update_idletasks()
    root.update()
    bar.set(*cv.yview())
    root.update_idletasks()
    h = bar.winfo_height()
    f, l = bar._first, bar._last
    # 可见比例＝canvas 高 / 内容高；内容 900、视口 300 时应该是 1/3
    vis = min(1.0, cv.winfo_height() / 900.0)
    chk(0.0 <= f < 0.01 and abs((l - f) - vis) < 0.02,
        "初始在顶部 %.3f..%.3f（可见比例应 %.2f）" % (f, l, vis))
    span = bar._span[1] - bar._span[0]
    want = int((l - f) * h)
    chk(abs(span - want) <= 2, "滑块长度按比例 %d vs %d" % (span, want))

    # --- 3. 拖滑块到底 ---
    bar._on_press(Ev(y=bar._span[0] + 5))
    bar._on_motion(Ev(y=h + 500))          # 拖出视口外，应被夹住
    bar._on_release()
    root.update_idletasks()
    chk(bar._last > 0.999, "拖到底 last=1.0（实际 %.3f）" % bar._last)
    chk(bar._span[1] <= h, "到底时滑块不探出视口 %s <= %d" % (bar._span[1], h))

    # --- 4. 拖回顶部 ---
    bar._on_press(Ev(y=bar._span[0] + 5))
    bar._on_motion(Ev(y=-500))
    bar._on_release()
    root.update_idletasks()
    chk(bar._first < 0.001, "拖回顶部 first=0（实际 %.3f）" % bar._first)

    # --- 5. 点轨道：跳过去，不是滚一屏 ---
    y_track = bar._span[1] + 40 if bar._span[1] + 40 < h - 20 else h - 5
    bar._on_press(Ev(y=y_track))
    bar._on_release()
    root.update_idletasks()
    chk(bar._first > 0.01, "点轨道跳过去了 first=%.3f" % bar._first)
    chk(bar._span[0] <= y_track + 2, "跳过去之后滑块到了指针附近 %s vs %d"
        % (bar._span, y_track))

    # --- 6. 滚轮 ---
    cv.yview_moveto(0.0)
    root.update_idletasks()
    before = bar._first
    bar._on_wheel(Ev(delta=-120))           # 向下
    root.update_idletasks()
    chk(bar._first > before, "滚轮向下 first 变大 %.3f -> %.3f" % (before, bar._first))
    mid = bar._first
    bar._on_wheel(Ev(delta=120))            # 向上
    root.update_idletasks()
    chk(bar._first < mid, "滚轮向上 first 变小 %.3f -> %.3f" % (mid, bar._first))

    # --- 7. 内容极长：滑块不小于 MIN_THUMB ---
    cv.destroy()
    bar.destroy()
    cv, bar = build(root, 40000)
    root.update_idletasks()
    root.update()
    bar.set(*cv.yview())
    root.update_idletasks()
    span = bar._span[1] - bar._span[0]
    chk(span >= MIN_THUMB, "极长内容滑块不小于 %d（实际 %d）" % (MIN_THUMB, span))

    # --- 8. 没绑 target 时滚轮不抛异常 ---
    lone = ThinBar(root)
    lone.pack()
    root.update_idletasks()
    try:
        lone._on_wheel(Ev(delta=-120))
        ok, err = True, ""
    except Exception as e:                 # noqa: BLE001
        ok, err = False, str(e)
    chk(ok, "没绑 target 时滚轮安全 %s" % err)

    root.destroy()
    print()
    if FAIL:
        print("通过 %d 项，失败 %d 项" % (0, len(FAIL)))
        for f in FAIL:
            print("  XX", f)
        return 1
    print("全部通过")
    return 0


if __name__ == "__main__":
    sys.exit(main())
