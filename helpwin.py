"""使用说明窗口 + 关于窗口（V1）。

为什么不塞进主界面日志区：说明有一万多字，塞进去会把日志挤没；日志是这工具
唯一的事后证据，不能给说明让位。所以单独一个 Toplevel，可以边看边操作。

配色在这里复写了一份，**没有 import roottool** —— 打包后入口脚本是以 `__main__`
跑的，`import roottool` 会把整个模块再加载一遍，常量、类、GP_ENABLED 全部两份，
排查时非常误导。代价是这 8 个色值与 roottool.py 重复，改配色两边一起改。
"""

from __future__ import annotations

import tkinter as tk
import webbrowser
from tkinter import filedialog, ttk

import helpdoc

BG = "#1e1e1e"
BG2 = "#252526"
BG3 = "#2d2d30"
FG = "#d4d4d4"
FG_DIM = "#8a8a8a"
ACCENT = "#0e639c"
OK_C = "#4ec9b0"
WARN_C = "#dcdcaa"

FONT = "Microsoft YaHei UI"
FONT_MONO = "Consolas"

HOME = "https://github.com/350886/leaf5-roottool"

TAGS = {
    "h": dict(font=(FONT, 11, "bold"), foreground="#4c9aff", spacing1=12, spacing3=4),
    "p": dict(font=(FONT, 10), foreground=FG, spacing3=2),
    "li": dict(font=(FONT, 10), foreground=FG, lmargin1=18, lmargin2=32, spacing3=1),
    "note": dict(font=(FONT, 9), foreground=FG_DIM, lmargin1=34, lmargin2=34,
                 spacing1=2, spacing3=3),
    "warn": dict(font=(FONT, 9), foreground=WARN_C, lmargin1=34, lmargin2=34,
                 spacing1=2, spacing3=3),
    "code": dict(font=(FONT_MONO, 9), foreground=OK_C, lmargin1=34, lmargin2=34,
                 spacing3=1),
    "hit": dict(background="#4a3b12", foreground="#ffd479"),
}


def render(text: tk.Text, body: str) -> list[int]:
    """把一段正文画进 Text，返回**每行在 Text 里的字符偏移**（搜索定位用）。

    按行号数不行：Text 的逻辑行和源文件行不是一回事，长行会软换行。
    """
    offsets: list[int] = []
    pos = 0
    for raw in body.splitlines():
        if raw.startswith("## "):
            line, tag = raw[3:], "h"
        elif raw.startswith("- "):
            line, tag = "• " + raw[2:], "li"
        elif raw.startswith("· "):
            line, tag = raw[2:], "li"
        elif raw.startswith("! "):
            line, tag = "⚠ " + raw[2:], "warn"
        elif raw.startswith("> "):
            line, tag = "› " + raw[2:], "note"
        elif raw.startswith("|"):
            line, tag = raw[1:], "code"
        else:
            line, tag = raw, "p"
        offsets.append(pos)
        text.insert("end", line + "\n", tag)
        pos += len(line) + 1
    return offsets


class HelpWindow(tk.Toplevel):
    def __init__(self, master) -> None:
        super().__init__(master)
        self.title("使用说明 — " + (master.title() or "Leaf5 Root Tool"))
        self.configure(bg=BG)
        self.geometry("880x640")
        self.minsize(720, 440)
        try:
            self.transient(master)
        except Exception:
            pass

        self._offsets: list[int] = []
        self._hits: list[tuple[int, int]] = []
        self._hits_word = ""
        self._hit_i = -1
        self._cur = 0

        head = tk.Frame(self, bg=BG2)
        head.pack(fill="x")
        tk.Label(head, text="使用说明", bg=BG2, fg=FG,
                 font=(FONT, 12, "bold")).pack(side="left", padx=(14, 10), pady=8)
        tk.Label(head, text="F1 打开 · Ctrl+F 搜索 · Esc 关闭", bg=BG2, fg=FG_DIM,
                 font=(FONT, 9)).pack(side="left")

        self.var_q = tk.StringVar()
        ent = tk.Entry(head, textvariable=self.var_q, width=22, bg=BG3, fg=FG,
                       insertbackground=FG, relief="flat", font=(FONT, 9))
        ent.pack(side="right", padx=(6, 14), pady=8)
        self.entry = ent
        ent.bind("<Return>", lambda _e: self.find_next(1))
        ent.bind("<Shift-Return>", lambda _e: self.find_next(-1))
        ent.bind("<Escape>", lambda _e: self._clear_find())
        tk.Label(head, text="搜索", bg=BG2, fg=FG_DIM,
                 font=(FONT, 9)).pack(side="right")
        self.lbl_find = tk.Label(head, text="", bg=BG2, fg=FG_DIM, font=(FONT, 9))
        self.lbl_find.pack(side="right", padx=(0, 8))

        body = tk.Frame(self, bg=BG)
        body.pack(fill="both", expand=True, padx=12, pady=(10, 0))

        left = tk.Frame(body, bg=BG, width=172)
        left.pack(side="left", fill="y")
        left.pack_propagate(False)
        self.list = tk.Listbox(left, bg=BG2, fg=FG, selectbackground=ACCENT,
                               selectforeground="#ffffff", relief="flat", bd=0,
                               highlightthickness=0, activestyle="none",
                               font=(FONT, 10), exportselection=False, width=16)
        self.list.pack(fill="both", expand=True)
        for name, _ in helpdoc.sections():
            self.list.insert("end", "  " + name)
        self.list.bind("<<ListboxSelect>>", self._on_pick)

        right = tk.Frame(body, bg=BG)
        right.pack(side="left", fill="both", expand=True, padx=(10, 0))
        self.text = tk.Text(right, bg="#141414", fg=FG, insertbackground=FG,
                            relief="flat", wrap="word", bd=0, padx=14, pady=10,
                            spacing2=2, state="disabled", cursor="arrow")
        sb = ttk.Scrollbar(right, orient="vertical", command=self.text.yview)
        self.text.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        self.text.pack(side="left", fill="both", expand=True)
        for tag, spec in TAGS.items():
            self.text.tag_config(tag, **spec)

        foot = tk.Frame(self, bg=BG2)
        foot.pack(fill="x", pady=(8, 0))
        tk.Button(foot, text="关闭", command=self.destroy, bg=BG3, fg=FG,
                  activebackground=BG2, activeforeground=FG, relief="flat", bd=0,
                  width=8, cursor="hand2",
                  font=(FONT, 9)).pack(side="right", padx=(6, 14), pady=6)
        tk.Button(foot, text="导出为 txt", command=self.export, bg=BG3, fg=FG,
                  activebackground=BG2, activeforeground=FG, relief="flat", bd=0,
                  width=10, cursor="hand2",
                  font=(FONT, 9)).pack(side="right", padx=6, pady=6)
        tk.Button(foot, text="打开项目主页", command=lambda: webbrowser.open(HOME),
                  bg=BG3, fg=FG, activebackground=BG2, activeforeground=FG,
                  relief="flat", bd=0, width=12, cursor="hand2",
                  font=(FONT, 9)).pack(side="right", padx=6, pady=6)
        self.lbl_foot = tk.Label(foot, text="", bg=BG2, fg=FG_DIM, font=(FONT, 9))
        self.lbl_foot.pack(side="left", padx=14)

        self.bind("<Escape>", lambda _e: self.destroy())
        self.bind("<Control-f>", lambda _e: self._focus_find())
        self.bind("<F1>", lambda _e: self.destroy())
        self.show(0)

    def show(self, idx: int) -> None:
        secs = helpdoc.sections()
        idx = max(0, min(idx, len(secs) - 1))
        self._cur = idx
        name, body = secs[idx]
        self.text.configure(state="normal")
        self.text.delete("1.0", "end")
        self._offsets = render(self.text, body)
        self.text.configure(state="disabled")
        self.text.yview_moveto(0)
        self.list.selection_clear(0, "end")
        self.list.selection_set(idx)
        self.list.see(idx)
        self.lbl_foot.configure(text="第 %d/%d 节 · %s"
                                % (idx + 1, len(secs), name))

    def _on_pick(self, _e=None) -> None:
        sel = self.list.curselection()
        if sel and sel[0] != self._cur:
            self.show(sel[0])

    def _focus_find(self) -> str:
        self.entry.focus_set()
        self.entry.selection_range(0, "end")
        return "break"

    def _clear_find(self) -> str:
        self.text.tag_remove("hit", "1.0", "end")
        self.var_q.set("")
        self.lbl_find.configure(text="")
        self._hits, self._hit_i = [], -1
        return "break"

    def find_next(self, step: int = 1) -> None:
        word = self.var_q.get().strip()
        if not word:
            self._clear_find()
            return
        if not self._hits or self._hits_word != word:
            self._hits = helpdoc.search(word)
            self._hits_word = word
            self._hit_i = -1
        if not self._hits:
            self.lbl_find.configure(text="没有匹配")
            self.text.tag_remove("hit", "1.0", "end")
            return
        self._hit_i = (self._hit_i + step) % len(self._hits)
        sec, line_no = self._hits[self._hit_i]
        if sec != self._cur:
            self.show(sec)
        self._highlight(word, line_no)
        self.lbl_find.configure(text="第 %d/%d 处"
                                % (self._hit_i + 1, len(self._hits)))

    def _highlight(self, word: str, line_no: int) -> None:
        self.text.tag_remove("hit", "1.0", "end")
        if line_no >= len(self._offsets):
            return
        start = "1.0 + %d chars" % self._offsets[line_no]
        pos = self.text.search(word, start, stopindex="end", nocase=True)
        if not pos:
            return
        self.text.tag_add("hit", pos, "%s + %d chars" % (pos, len(word)))
        self.text.see(pos)
        self.text.yview_scroll(-2, "units")

    def export(self) -> None:
        try:
            path = export_plain(self)
        except OSError as e:
            self.lbl_foot.configure(text="导出失败：%s" % e)
            return
        if path:
            self.lbl_foot.configure(text="已导出：%s" % path)


def export_plain(master) -> str | None:
    """整份说明存成 txt。取消返回 None，写失败抛 OSError 给调用方显示。"""
    path = filedialog.asksaveasfilename(
        parent=master, title="导出使用说明", defaultextension=".txt",
        initialfile="Leaf5RootTool-使用说明.txt",
        filetypes=[("文本文件", "*.txt"), ("所有文件", "*.*")])
    if not path:
        return None
    with open(path, "w", encoding="utf-8", newline="\r\n") as f:
        f.write(helpdoc.plain())
    return path


def open_help(master) -> HelpWindow:
    """同一个窗口只开一个：连按两次 F1 不该叠出两个。"""
    for w in master.winfo_children():
        if isinstance(w, HelpWindow) and w.winfo_exists():
            w.show(w._cur)
            w.lift()
            w.focus_set()
            return w
    return HelpWindow(master)


class AboutWindow(tk.Toplevel):
    def __init__(self, master, app_name="Leaf5 Root Tool", app_ver="",
                 model="", firmware="", kernel="") -> None:
        super().__init__(master)
        self.title("关于 " + app_name)
        self.configure(bg=BG)
        self.resizable(False, False)
        try:
            self.transient(master)
        except Exception:
            pass

        pad = tk.Frame(self, bg=BG)
        pad.pack(fill="both", expand=True, padx=22, pady=18)
        tk.Label(pad, text=app_name, bg=BG, fg=FG,
                 font=(FONT, 16, "bold")).pack(anchor="w")
        tk.Label(pad, text="v" + app_ver, bg=BG, fg=FG_DIM,
                 font=(FONT, 10)).pack(anchor="w", pady=(0, 10))

        body = ("ONYX BOOX Leaf5 的一键 root 客户端，内嵌 adb，不依赖机器上装没装\n"
                "platform-tools。载荷来自 GhostLock（CVE-2026-43499，rtmutex 栈 UAF）。\n\n"
                "写 boot 有三条通路：dd（有 root）、fastbootd（无 root，走 userspace）、\n"
                "EDL/9008（兜底）。ONYX 的 abl 裁掉了 bootloader 的 flash 命令，\n"
                "所以 fastbootd 是没 root 时的主通路。")
        tk.Label(pad, text=body, bg=BG, fg=FG, justify="left",
                 font=(FONT, 9)).pack(anchor="w")

        ttk.Separator(pad, orient="horizontal").pack(fill="x", pady=12)
        for line in ("仅适用：%s" % model if model else "",
                     "固件：%s" % firmware if firmware else "",
                     "内核：%s" % kernel if kernel else ""):
            if line:
                tk.Label(pad, text=line, bg=BG, fg=FG_DIM,
                         font=(FONT, 8)).pack(anchor="w")
        tk.Label(pad, text="许可证：MIT", bg=BG, fg=FG_DIM,
                 font=(FONT, 8)).pack(anchor="w")

        bar = tk.Frame(pad, bg=BG)
        bar.pack(fill="x", pady=(14, 0))
        tk.Button(bar, text="打开项目主页", command=lambda: webbrowser.open(HOME),
                  bg=BG3, fg=FG, activebackground=BG2, activeforeground=FG,
                  relief="flat", bd=0, width=13, cursor="hand2",
                  font=(FONT, 9)).pack(side="left")
        tk.Button(bar, text="关闭", command=self.destroy, bg=ACCENT, fg="#ffffff",
                  activebackground="#1177bb", activeforeground="#ffffff",
                  relief="flat", bd=0, width=8, cursor="hand2",
                  font=(FONT, 9)).pack(side="right")
        self.bind("<Escape>", lambda _e: self.destroy())


def open_about(master, **kw) -> None:
    AboutWindow(master, **kw).focus_set()
