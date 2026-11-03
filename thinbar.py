"""自绘细滚动条。

为什么不用现成的：

- `ttk.Scrollbar` 在 Windows 的 vista 主题下，`width` 被主题接管，实际画出来是
  17px 的浅灰块 —— 深色窗口边上镶一条白边，很脏；`style` 能改的颜色也有限。
- `tk.Scrollbar` 能设 `width`，但 trough 颜色只在经典主题生效，vista 下依然灰块。

所以自己拿 Canvas 画：8px 宽、滑块圆角、悬停提亮。代价是要自己实现拖动和
点击跳转，下面这些回调就是干这个的。

用法和 Scrollbar 一样：把它挂给目标 Canvas 的 `yscrollcommand`，再把
`command=target.yview` 交回来。V1 里用 `from thinbar import ThinBar`（不带包前缀）。

    bar = ThinBar(parent, command=cv.yview, target=cv)
    cv.configure(yscrollcommand=bar.set)
"""

import tkinter as tk

# 滑块最短高度。太短时拖不中 —— 内容长十倍时按比例算只有几像素。
MIN_THUMB = 18


class ThinBar(tk.Canvas):
    def __init__(self, master, command=None, target=None, width=8,
                 trough="#26282c", thumb="#55595f", hover="#6c7178",
                 offtrack="#232528", bg="#1e1f22", **kw):
        super().__init__(master, width=width, highlightthickness=0, bd=0,
                         bg=bg, takefocus=0, **kw)
        self._command = command
        self._target = target      # 滚轮要在它上面生效
        self._bar_w = width   # 不能叫 _w：tkinter 用 Misc._w 存 Tcl 窗口名，
        # 覆盖成数字后 pack 会报 bad argument 8: must be name of window
        self._c_trough = trough
        self._c_thumb = thumb
        self._c_hover = hover
        self._c_off = offtrack
        self._first = 0.0
        self._last = 1.0
        self._hot = False
        self._grab_dy = None       # 拖滑块时，指针相对滑块顶的偏移
        self._span = (0, 0)

        self.bind("<Configure>", lambda _e: self._draw())
        self.bind("<Enter>", self._on_enter)
        self.bind("<Leave>", self._on_leave)
        self.bind("<ButtonPress-1>", self._on_press)
        self.bind("<B1-Motion>", self._on_motion)
        self.bind("<ButtonRelease-1>", self._on_release)
        for seq in ("<MouseWheel>", "<Button-4>", "<Button-5>"):
            self.bind(seq, self._on_wheel)

    # ---------------- 对外 ----------------

    def set(self, first, last, *args):
        """给 canvas 的 yscrollcommand 调用。多余的参数是 tk 的回调签名要求。"""
        try:
            self._first = float(first)
            self._last = float(last)
        except (TypeError, ValueError):
            return
        self._draw()

    # ---------------- 绘制 ----------------

    def _draw(self) -> None:
        h = self.winfo_height()
        if h <= 1:                 # 还没布局，等 <Configure> 再来
            return
        self.delete("all")
        f, l = self._first, self._last
        # 内容一屏装得下时只画轨道、不画滑块 —— 画一个满格滑块会让人
        # 以为还能往下滚，白拖两下才知道到底了。
        full = (l - f) >= 0.9995
        self.create_rectangle(0, 0, self._bar_w, h, width=0,
                              fill=self._c_off if full else self._c_trough)
        if full:
            self._span = (0, 0)
            return
        span = max(MIN_THUMB, int((l - f) * h))
        y0 = int(f * h)
        if y0 + span > h:           # 到底时别让滑块探出视口
            y0 = h - span
        self._span = (y0, y0 + span)
        self.create_rectangle(1, y0 + 1, self._bar_w - 1, y0 + span - 1, width=0,
                              fill=self._c_hover if self._hot else self._c_thumb)

    # ---------------- 交互 ----------------

    def _on_enter(self, _e=None):
        self._hot = True
        self._draw()

    def _on_leave(self, _e=None):
        self._hot = False
        self._draw()

    def _on_press(self, e):
        y0, y1 = self._span
        if y1 <= y0:                # 没有滑块，什么都不滚
            return
        if y0 <= e.y <= y1:
            self._grab_dy = e.y - y0
        else:
            # 点轨道＝跳过去，并且把滑块中心对到指针上，接着就能拖
            self._grab_dy = (y1 - y0) // 2
            self._on_motion(e)

    def _on_motion(self, e):
        if self._grab_dy is None or not self._command:
            return
        h = self.winfo_height()
        if h <= 1:
            return
        vis = self._last - self._first
        want = (e.y - self._grab_dy) / float(h)
        # moveto 收的是「可视区顶部位置」，最大只能到 1 - 可见比例，
        # 超了 canvas 会自己夹住，但先夹一遍省得滑块先跳再弹回。
        self._command("moveto", max(0.0, min(1.0 - vis, want)))

    def _on_release(self, _e=None):
        self._grab_dy = None

    def _on_wheel(self, e):
        t = self._target
        if t is None:
            return
        step = 3                     # 一格滚三行，和日志区手感一致
        down = (getattr(e, "num", None) == 5
                or getattr(e, "delta", 0) < 0)
        up = (getattr(e, "num", None) == 4
              or getattr(e, "delta", 0) > 0)
        if down:
            t.yview_scroll(step, "units")
        elif up:
            t.yview_scroll(-step, "units")
        return "break"               # 别让 bind_all 上的处理器再滚一遍
