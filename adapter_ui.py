# -*- coding: utf-8 -*-
"""
adapter_ui.py — 「内核适配向导」窗口。

给"换了固件 / 换了内核"的机器重新生成 preload.so 用。
不依赖主窗口，单独 Toplevel，关掉不影响正在跑的 root 流程。

五步：
  ① 内核来源 —— 打开即自动查找（记忆 → 常见目录 → 全盘），可切候选
  ② 备好 NDK（本机有就复用，没有就下载）
  ③ 解出 vmlinux → 提符号 → 生成 target.h
  ④ 人工填 4 个结构体/栈常量（窗口里给了解释）
  ⑤ 编译 → 装进工具，之后主界面直接用它

所有耗时动作都在后台线程，UI 只吃 queue 消息。
"""

import os
import queue
import shutil
import threading
import time
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

import adapter
import elfsyms
import ndkman

BG = "#1e1e1e"
BG2 = "#252526"
BG3 = "#2d2d30"
FG = "#d4d4d4"
FG_DIM = "#8a8a8a"
ACCENT = "#0e639c"
OK_C = "#4ec9b0"
BAD_C = "#f48771"
WARN_C = "#dcdcaa"

FONT = ("Microsoft YaHei UI", 9)
MONO = ("Consolas", 9)


class AdapterWindow(object):
    def __init__(self, master, app=None, autoscan=True):
        self.app = app                    # 主窗口，用来取 adb 实例（可空）
        self.q = queue.Queue()
        self.busy = False
        self.elf_path = None
        self.tdir = None
        self.so_path = None
        self.ndk_root = None
        self.ndk_cc = None
        self.diffs = []
        self.meta = {}
        self._banner_cache = {}           # path -> linux_banner 原文（切 96MB 镜像不便宜）
        self.cands = []                   # 自动找到的可用内核（带符号 ELF）
        self.others = []                  # 找到了但用不上（boot.img / strip 过）
        self._disk_stop = None            # 全盘扫描的取消开关
        self._deep_done = False           # 打开向导时那轮深扫跑过没有
        self._cand_win = None             # 候选浮层

        self.win = tk.Toplevel(master)
        self.win.title("内核适配向导 — 换固件后用")
        self.win.geometry("880x760")
        self.win.minsize(760, 620)
        self.win.configure(bg=BG)
        self.win.transient(master)

        self._build()
        self._poll()
        self.win.after(200, lambda: self._check_ndk(quiet=True))
        if autoscan:
            self.win.after(260, self._autoscan)

    # ------------------------------------------------------------------
    def _build(self):
        pad = {"padx": 12}

        # 顶部说明
        head = tk.Frame(self.win, bg=BG)
        head.pack(fill="x", **pad, pady=(12, 4))
        tk.Label(head, text="给另一版内核重新编译载荷",
                 bg=BG, fg=FG, font=("Microsoft YaHei UI", 12, "bold")).pack(anchor="w")
        tk.Label(head,
                 text="内置的 preload.so 只对 ONYX 4.2.3-rel_0928（内核 4.19.157 #38）成立。"
                      "换固件后符号偏移全变，要按这台机器的 vmlinux 重编一次。",
                 bg=BG, fg=FG_DIM, font=FONT, justify="left", wraplength=840).pack(anchor="w", pady=(3, 0))

        # ① 输入
        f1 = tk.LabelFrame(self.win, text=" ①  内核来源（打开即自动查找） ", bg=BG2,
                           fg=FG_DIM, font=FONT, bd=0, highlightthickness=0)
        f1.pack(fill="x", **pad, pady=8)

        row = tk.Frame(f1, bg=BG2)
        row.pack(fill="x", padx=10, pady=(8, 4))
        self.ent_src = tk.Entry(row, bg=BG3, fg=FG, insertbackground=FG,
                                relief="flat", font=MONO)
        self.ent_src.pack(side="left", fill="x", expand=True, ipady=3)
        tk.Button(row, text="浏览…", command=self._browse, bg=BG3, fg=FG,
                  relief="flat", font=FONT, activebackground=ACCENT,
                  activeforeground="#fff", bd=0, padx=10).pack(side="left", padx=(6, 0))

        hint = tk.Frame(f1, bg=BG2)
        hint.pack(fill="x", padx=10, pady=(0, 8))
        self.lbl_scan = tk.Label(
            hint, text="正在找本机的内核镜像…", bg=BG2, fg=FG_DIM,
            font=("Microsoft YaHei UI", 8), anchor="w", justify="left",
            wraplength=460)      # 右侧并排三个按钮，留够宽度，窄窗口下先换行不挤压
        self.lbl_scan.pack(side="left", fill="x", expand=True)
        self.btn_disk = tk.Button(
            hint, text="全盘搜", command=self._do_disk_scan, bg=BG3, fg=FG,
            relief="flat", font=("Microsoft YaHei UI", 8), bd=0, padx=8,
            activebackground=ACCENT, activeforeground="#fff")
        self.btn_disk.pack(side="right", padx=(6, 0))
        # 设备已 root 时这是最快的路：符号偏移全是「符号 − _text」的差值，
        # /proc/kallsyms 完全能替代 vmlinux.elf，不用去翻固件包
        self.btn_dev = tk.Button(
            hint, text="从设备读符号", command=self._do_kallsyms, bg=BG3, fg=FG,
            relief="flat", font=("Microsoft YaHei UI", 8), bd=0, padx=8,
            activebackground=ACCENT, activeforeground="#fff")
        self.btn_dev.pack(side="right", padx=(6, 0))
        self.btn_cand = tk.Button(
            hint, text="候选", command=self._pop_cand, bg=BG3, fg=FG_DIM,
            relief="flat", font=("Microsoft YaHei UI", 8), bd=0, padx=8,
            state="disabled",
            activebackground=ACCENT, activeforeground="#fff")
        self.btn_cand.pack(side="right")

        # 设备判定行：没 root 也能回答"这台机器该不该用现成载荷"
        # 判据是 /proc/kallsyms 的符号名序列 —— 地址被 kptr_restrict 清零不影响名字
        rowfp = tk.Frame(f1, bg=BG2)
        rowfp.pack(fill="x", padx=10, pady=(0, 8))
        # 不需要 root 也不需要在网上找固件：走 9008 下载模式，
        # 用 firehose programmer 按 GPT 表只读当前槽的 boot 分区。
        self.btn_edl = tk.Button(
            rowfp, text="EDL 读 boot", command=self._do_edl, bg=BG3, fg=ACCENT,
            relief="flat", font=("Microsoft YaHei UI", 8), bd=0, padx=8,
            activebackground=ACCENT, activeforeground="#fff")
        self.btn_edl.pack(side="left")
        self.btn_fp = tk.Button(
            rowfp, text="读设备指纹", command=self._do_fp, bg=BG3, fg=FG,
            relief="flat", font=("Microsoft YaHei UI", 8), bd=0, padx=8,
            activebackground=ACCENT, activeforeground="#fff")
        self.btn_fp.pack(side="left", padx=(6, 0))
        self.lbl_fp = tk.Label(
            rowfp, text="没 root 也能判断这台设备的内核认不认得出来",
            bg=BG2, fg=FG_DIM, font=("Microsoft YaHei UI", 8), anchor="w",
            justify="left", wraplength=560)
        self.lbl_fp.pack(side="left", fill="x", expand=True, padx=(8, 0))
        self.dev_fp = None

        # 候选清单直接摊在窗口里，不用下拉菜单 ——
        # 原生 tk.Menu 在 Windows 上不吃 bg/fg（深色窗口里弹白板），
        # 无边框 Toplevel 又抢不到焦点（overrideredirect 窗口 FocusOut 立刻触发，
        # 刚弹出就被自己关掉）。嵌在面板里最稳，也没有层级问题。
        self.lb_cand = tk.Listbox(
            f1, bg=BG3, fg=FG, selectbackground=ACCENT, selectforeground="#ffffff",
            bd=0, highlightthickness=1, highlightbackground="#3c3c3c",
            font=("Microsoft YaHei UI", 9), activestyle="none",
            exportselection=False, height=8)
        self.lb_cand.bind("<ButtonRelease-1>", self._pick_cand)
        self._cand_open = False
        self._cand_rows = []

        # ② NDK
        f2 = tk.LabelFrame(self.win, text=" ②  交叉编译工具链 ", bg=BG2, fg=FG_DIM,
                           font=FONT, bd=0, highlightthickness=0)
        f2.pack(fill="x", **pad, pady=(0, 8))

        r2 = tk.Frame(f2, bg=BG2)
        r2.pack(fill="x", padx=10, pady=(8, 4))
        self.lbl_ndk = tk.Label(r2, text="检查中…", bg=BG2, fg=FG_DIM,
                                font=FONT, anchor="w")
        self.lbl_ndk.pack(side="left", fill="x", expand=True)
        tk.Button(r2, text="重新检测", command=lambda: self._check_ndk(False),
                  bg=BG3, fg=FG, relief="flat", font=FONT, bd=0, padx=8,
                  activebackground=ACCENT, activeforeground="#fff").pack(side="left")
        tk.Button(r2, text="下载 NDK（约 700MB）", command=lambda: self._check_ndk(False, True),
                  bg=BG3, fg=FG, relief="flat", font=FONT, bd=0, padx=8,
                  activebackground=ACCENT, activeforeground="#fff").pack(side="left", padx=(6, 0))

        # ③ 生成 / 编译 / 安装
        f3 = tk.LabelFrame(self.win, text=" ③  生成与编译 ", bg=BG2, fg=FG_DIM,
                           font=FONT, bd=0, highlightthickness=0)
        f3.pack(fill="x", **pad, pady=(0, 8))
        r3 = tk.Frame(f3, bg=BG2)
        r3.pack(fill="x", padx=10, pady=10)
        self.btn_unpack = self._btn(r3, "解出 vmlinux", self._do_unpack)
        self.btn_unpack.pack(side="left")
        self.btn_gen = self._btn(r3, "生成 target.h", self._do_gen)
        self.btn_gen.pack(side="left", padx=6)
        self.btn_open = self._btn(r3, "打开 target.h", self._open_target)
        self.btn_open.pack(side="left")
        self.btn_compile = self._btn(r3, "编译 preload.so", self._do_compile, primary=True, w=16)
        self.btn_compile.pack(side="left", padx=(18, 6))
        self.btn_install = self._btn(r3, "装进工具", self._do_install)
        self.btn_install.pack(side="left")

        # 差异表：用只读 Text 而不是 ttk.Treeview —— 原生主题的表头是白底，
        # 在深色窗口里刺眼，且 Win 的 vista 主题不吃 background 配置
        f4 = tk.LabelFrame(self.win, text=" 符号偏移对比（模板 vs 本机 vmlinux） ",
                           bg=BG2, fg=FG_DIM, font=FONT, bd=0, highlightthickness=0)
        f4.pack(fill="both", expand=True, **pad, pady=(0, 8))

        tf = tk.Frame(f4, bg=BG2)
        tf.pack(fill="both", expand=True, padx=6, pady=6)
        self.tbl = tk.Text(tf, bg="#141414", fg=FG, relief="flat", wrap="none",
                           font=MONO, height=7, state="disabled")
        tsb = tk.Scrollbar(tf, command=self.tbl.yview, bg=BG3, troughcolor=BG2)
        self.tbl.configure(yscrollcommand=tsb.set)
        tsb.pack(side="right", fill="y")
        self.tbl.pack(side="left", fill="both", expand=True)
        self.tbl.tag_config("hdr", foreground=FG_DIM)
        self.tbl.tag_config("diff", foreground=WARN_C)
        self.tbl.tag_config("note", foreground=FG_DIM)

        # 待填提示
        f5 = tk.Frame(self.win, bg=BG2)
        f5.pack(fill="x", **pad, pady=(0, 8))
        self.lbl_fill = tk.Label(
            f5, text="待填：4 个结构体 / 栈常量（生成 target.h 后这里会列出）",
            bg=BG2, fg=WARN_C, font=("Microsoft YaHei UI", 8),
            justify="left", anchor="w", wraplength=840)
        self.lbl_fill.pack(fill="x", padx=10, pady=8)

        # 日志
        lf = tk.Frame(self.win, bg=BG)
        lf.pack(fill="both", expand=True, **pad, pady=(0, 6))
        self.txt = tk.Text(lf, bg="#141414", fg="#c8c8c8", insertbackground=FG,
                           relief="flat", wrap="none", font=MONO, state="disabled",
                           height=10)
        sb = tk.Scrollbar(lf, command=self.txt.yview, bg=BG3, troughcolor=BG2)
        self.txt.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        self.txt.pack(side="left", fill="both", expand=True)
        self.txt.tag_config("ok", foreground=OK_C)
        self.txt.tag_config("bad", foreground=BAD_C)
        self.txt.tag_config("warn", foreground=WARN_C)
        self.txt.tag_config("dim", foreground=FG_DIM)

        # 底部
        foot = tk.Frame(self.win, bg=BG)
        foot.pack(fill="x", **pad, pady=(0, 8))
        self.pb = ttk.Progressbar(foot, mode="determinate", maximum=100, length=200)
        self.pb.pack(side="right")
        self.lbl_state = tk.Label(foot, text="待机", bg=BG, fg=FG_DIM,
                                  font=FONT, anchor="w")
        self.lbl_state.pack(side="left", fill="x", expand=True)

    def _btn(self, parent, text, cmd, primary=False, w=13):
        return tk.Button(parent, text=text, command=cmd, width=w,
                         bg=ACCENT if primary else BG3, fg="#ffffff" if primary else FG,
                         relief="flat", font=FONT, bd=0, pady=4,
                         activebackground="#1177bb" if primary else "#3a3a3d",
                         activeforeground="#ffffff")

    # ------------------------------------------------------------------
    # 线程与消息
    # ------------------------------------------------------------------
    def _poll(self):
        try:
            while True:
                kind, payload = self.q.get_nowait()
                if kind == "log":
                    self._append(payload[0], payload[1] if len(payload) > 1 else None)
                elif kind == "state":
                    self.lbl_state.configure(text=payload)
                elif kind == "prog":
                    cur, total, phase = payload
                    if total:
                        self.pb.configure(mode="determinate",
                                          value=cur * 100.0 / total)
                    self.lbl_state.configure(
                        text=f"{phase}  {cur * 100.0 / total:.1f}%" if total else phase)
                elif kind == "done":
                    self._set_busy(False)
                    self.lbl_state.configure(text=payload or "完成", fg=OK_C)
                elif kind == "err":
                    self._set_busy(False)
                    msg = str(payload)
                    # AdapterError 这类前缀对使用者没意义，剥掉
                    for pfx in ("AdapterError: ", "NdkError: ", "ElfError: "):
                        if msg.startswith(pfx):
                            msg = msg[len(pfx):]
                            break
                    self._append("\n[!] " + msg, "bad")
                    self.lbl_state.configure(text="失败", fg=BAD_C)
                elif kind == "fail":
                    self.lbl_state.configure(text=payload, fg=BAD_C)
                elif kind == "ndk":
                    root, cc = payload
                    self.ndk_root, self.ndk_cc = root, cc
                    self.lbl_ndk.configure(
                        text=f"已就绪  {os.path.basename(root)}", fg=OK_C)
                elif kind == "diffs":
                    self._fill_table(payload)
                elif kind == "target":
                    self.tdir = payload
                elif kind == "so":
                    self.so_path = payload
                elif kind == "fp":
                    f, res = payload
                    self.dev_fp = f
                    txt = res["why"] + "。" + res["advice"]
                    color = {"same_build": OK_C, "same_version": WARN_C,
                             "different": BAD_C,
                             "no_target": WARN_C}.get(res["verdict"], FG_DIM)
                    self.lbl_fp.configure(text=txt, fg=color)
                    tag = "ok" if res["verdict"] == "same_build" else "warn"
                    self._append(f"[·] 设备指纹：{res['why']}", tag)

                    # 手头这个镜像是不是设备上正在跑的那个？commit 一对就清楚了。
                    # 对不上还硬编，偏移会打偏、在内核里随机位置崩。
                    if self.elf_path:
                        bn = self._banner_of(self.elf_path)
                        dev_ver = (f.get("raw") or {}).get("version", "")
                        if bn and dev_ver:
                            v, why, adv = adapter.banner_match(bn, dev_ver)
                            if v == "different":
                                self._append(f"[X] 镜像与设备不是同一内核 —— {why}", "bad")
                                self._append(f"    {adv}", "warn")
                                self.lbl_scan.configure(
                                    text=f"镜像 {adapter.parse_banner(bn).get('commit')} "
                                         f"≠ 设备 {adapter.parse_banner(dev_ver).get('commit')}"
                                         f" —— 换设备当前 boot 分区的镜像",
                                    fg=BAD_C)
                            elif v in ("resame", "dirty"):
                                self._append(f"[!] {why}", "warn")
                            elif v == "same":
                                self._append(f"[✓] 镜像与设备同构建：{why}", "ok")
                elif kind == "edl":
                    d = payload
                    self._append(
                        f"[✓] 读出 {d['partition']}（{adapter.human_size(d['size'])}）"
                        f"→ {d['path']}", "ok")
                    self._take(d["path"])
                elif kind == "edlend":
                    self._set_busy(False)
                    self.btn_edl.configure(state="normal")
                elif kind == "fpend":
                    self._set_busy(False)
                elif kind == "ksyms":
                    path, st = payload
                    self._fill_src(path)
                    self.elf_path = path
                    self.lbl_scan.configure(
                        text=f"已从设备导出符号：{os.path.basename(path)}"
                             f"（{st['syms']} 个符号，"
                             f"_text 0x{st['text']:016X}）", fg=OK_C)
                    self._append(
                        f"[✓] {st['lines']} 行 / {st['syms']} 符号 → {path}", "ok")
                elif kind == "ksymsend":
                    self._set_busy(False)
                elif kind == "autopick":
                    self._fill_src(payload["path"])
                    self.elf_path = payload["path"]
                    self.lbl_scan.configure(
                        text=f"已自动填入上次用的内核：{os.path.basename(payload['path'])}"
                             f"（{adapter.human_size(payload['size'])}，{payload['note']}）",
                        fg=OK_C)
                elif kind == "scan":
                    self._apply_scan(*payload)
                elif kind == "scanend":
                    # payload=True 表示这一轮是打开向导时的自动查找，要解 busy；
                    # 后台深扫不占 busy，不能顺手把用户正在跑的编译解禁
                    self._disk_stop = None
                    self.btn_disk.configure(text="全盘搜", state="normal", fg=FG)
                    if payload:
                        self._set_busy(False)
                elif kind == "scanempty":
                    self._on_scan_empty(payload)
        except queue.Empty:
            pass
        if self.win.winfo_exists():
            self.win.after(150, self._poll)

    def _append(self, s, tag=None):
        self.txt.configure(state="normal")
        self.txt.insert("end", s + "\n", tag or "")
        self.txt.see("end")
        self.txt.configure(state="disabled")

    def _set_busy(self, b):
        self.busy = b
        st = "disabled" if b else "normal"
        for w in (self.btn_unpack, self.btn_gen, self.btn_compile,
                  self.btn_install, self.btn_open, self.btn_dev, self.btn_fp,
                  self.btn_edl):
            w.configure(state=st)
        self.win.configure(cursor="watch" if b else "")

    def _run(self, fn, label):
        if self.busy:
            return
        self._set_busy(True)
        self.lbl_state.configure(text=label, fg=FG)

        def wrap():
            ok = True
            try:
                fn()
            except Exception as e:
                ok = False
                self.q.put(("err", f"{type(e).__name__}: {e}"))
            finally:
                # 失败时不能发 done —— 它会把状态刷成绿色"结束"，盖掉红字
                if ok:
                    self.q.put(("done", label + " 结束"))
                else:
                    self.q.put(("fail", label + " 失败"))

        threading.Thread(target=wrap, daemon=True).start()

    def _log(self, s, tag=None):
        self.q.put(("log", (str(s), tag)))

    # ------------------------------------------------------------------
    # NDK
    # ------------------------------------------------------------------
    def _check_ndk(self, quiet=False, download=False):
        if self.busy:
            return
        self._set_busy(True)
        self.lbl_state.configure(text="检测 NDK…", fg=FG)

        def work():
            try:
                root, cc = ndkman.find_installed(log=self._log)
                if cc:
                    ndkman.verify(root, log=self._log)
                    self.q.put(("ndk", (root, cc)))
                elif download:
                    root, cc = ndkman.install(
                        progress=lambda i: self.q.put(
                            ("prog", (i["done"], i["total"], i["phase"]))),
                        log=self._log)
                    self.q.put(("ndk", (root, cc)))
                else:
                    if not quiet:
                        self._log("本机没有可用的 NDK。点「下载 NDK」开始拉取。", "warn")
                    self.q.put(("state", "NDK 未安装"))
            except Exception as e:
                self.q.put(("err", f"{type(e).__name__}: {e}"))
            finally:
                self.q.put(("done", ""))

        threading.Thread(target=work, daemon=True).start()

    # ------------------------------------------------------------------
    # ① 自动查找内核
    # ------------------------------------------------------------------
    def _fill_src(self, path):
        self.ent_src.delete(0, "end")
        self.ent_src.insert(0, path)

    def _autoscan(self):
        """
        打开向导就自动找一次：先看上次用过的还在不在（瞬间出结果），
        没有再扫常见目录（约 0.2~2 秒）。常见目录也没有就自动转后台深扫。
        """
        if self.busy:
            self.win.after(500, self._autoscan)
            return
        self._set_busy(True)
        self.lbl_scan.configure(text="正在找本机的内核镜像…", fg=FG_DIM)

        def work():
            try:
                recent = adapter.load_recent()
                if recent:
                    info = adapter.probe_kernel(recent[0])
                    if info and info.get("usable"):
                        self.q.put(("autopick", info))
                        return
                usable, others = adapter.scan_kernels(log=self._log)
                self.q.put(("scan", (usable, others)))
            except Exception as e:
                self.q.put(("err", f"{type(e).__name__}: {e}"))
            finally:
                self.q.put(("scanend", True))

        threading.Thread(target=work, daemon=True).start()

    def _apply_scan(self, usable, others):
        self.cands, self.others = usable, others
        if self._cand_open:                 # 上一轮的清单先收起来
            self.lb_cand.pack_forget()
            self._cand_open = False
        if usable:
            best = usable[0]
            self._fill_src(best["path"])
            self.elf_path = best["path"]
            txt = (f"自动找到 {len(usable)} 个带符号的内核，已选最大的一份："
                   f"{os.path.basename(best['path'])}"
                   f"（{adapter.human_size(best['size'])}，{best['note']}）")
            if len(usable) > 1:
                txt += "　点「候选」换别的"
            self.lbl_scan.configure(text=txt, fg=OK_C)
            self.btn_cand.configure(
                state="normal", fg=FG,
                text=f"候选 {len(usable)}" + (f"+{len(others)}" if others else ""))
            return

        self.btn_cand.configure(state="disabled", text="候选", fg=FG_DIM)
        if others:
            names = "、".join(os.path.basename(x["path"]) for x in others[:3])
            more = "…" if len(others) > 3 else ""
            self.lbl_scan.configure(
                text=f"没找到能用的内核。扫到 {len(others)} 个镜像"
                     f"（{names}{more}），但 kernel 段都解不出来 —— "
                     f"点「浏览…」指定一个 boot.img 或裸 Image",
                fg=WARN_C)
        else:
            self.lbl_scan.configure(text="常见目录没有，正在往深里扫…", fg=FG_DIM)
            self.win.after(120, lambda: self._start_scan(60.0, 6, manual=False))

    def _pop_cand(self):
        """展开 / 收起窗口内的候选清单"""
        if not (self.cands or self.others):
            return
        if self._cand_open:
            self.lb_cand.pack_forget()
            self._cand_open = False
            self.btn_cand.configure(text=self._cand_btn_label())
            return

        rows = []
        if self.cands:
            rows.append(("head", "—— 可用（带符号）—— ", None))
            for c in self.cands:
                rows.append(("use",
                             f"{os.path.basename(c['path'])}    "
                             f"{adapter.human_size(c['size'])}    {c['note']}",
                             c["path"]))
        if self.others:
            rows.append(("head", "—— 找到了但用不上 ——", None))
            for c in self.others[:12]:
                rows.append(("dis",
                             f"{os.path.basename(c['path'])}    "
                             f"{adapter.human_size(c['size'])}", None))
        self._cand_rows = rows

        lb = self.lb_cand
        lb.delete(0, "end")
        for kind, text, _p in rows:
            lb.insert("end", text)
            if kind == "head":
                lb.itemconfigure("end", foreground=FG_DIM, background=BG2)
            elif kind == "dis":
                lb.itemconfigure("end", foreground=FG_DIM)
        lb.configure(height=min(len(rows), 9))
        lb.pack(fill="x", padx=10, pady=(0, 8))
        self._cand_open = True
        self.btn_cand.configure(text="收起")

    def _cand_btn_label(self):
        n = len(self.cands)
        m = len(self.others)
        return f"候选 {n}" + (f"+{m}" if m else "")

    def _pick_cand(self, _evt=None):
        sel = self.lb_cand.curselection()
        if not sel:
            return
        kind, _t, path = self._cand_rows[sel[0]]
        if kind != "use":
            return
        self.lb_cand.pack_forget()
        self._cand_open = False
        self.btn_cand.configure(text=self._cand_btn_label())
        self._take(path)

    def _take(self, path, remember=True):
        """填进输入框并记住。remember 只对真能用的镜像开"""
        self._fill_src(path)
        self.elf_path = path
        info = adapter.probe_kernel(path, deep=False)
        size = info["size"] if info else 0

        # 顺手把镜像自己的构建身份读出来。这一步不用设备、不用 root：
        # linux_banner 就编在 kernel 里，跟设备 /proc/version 是同一个字符串。
        # 有它就能立刻回答"这个镜像是不是设备上正在跑的那个"。
        bn = self._banner_of(path)
        head = f"已选：{os.path.basename(path)}（{adapter.human_size(size)}）"
        if bn:
            b = adapter.parse_banner(bn)
            tail = " ".join(x for x in (b.get("version"),
                                        "#%s" % b["build"] if b.get("build") else "",
                                        b.get("commit") or "") if x)
            text, fg = f"{head} · {tail}", OK_C
            if b.get("dirty"):
                text, fg = f"{head} · {tail}（-dirty，commit 不完全可信）", WARN_C
        else:
            text, fg = f"{head} · 读不到 linux_banner", WARN_C
        self.lbl_scan.configure(text=text, fg=fg)
        if remember:
            adapter.remember_kernel(path)

    def _banner_of(self, path):
        """读镜像 banner 并缓存 —— 自动扫描会连着调好几次，别每次都切 96MB 镜像"""
        if path in self._banner_cache:
            return self._banner_cache[path]
        try:
            bn = adapter.read_kernel_banner(path)
        except Exception:
            bn = None
        self._banner_cache[path] = bn
        return bn

    def _start_scan(self, budget, depth, manual):
        """后台扫盘。manual=True 是用户点「全盘搜」，再点一次可停。"""
        if self._disk_stop is not None:
            self._disk_stop.set()
            self.btn_disk.configure(text="正在停…", state="disabled")
            return
        if not manual and (self.cands or self._deep_done):
            return
        if not manual:
            self._deep_done = True
        self._disk_stop = threading.Event()
        self.btn_disk.configure(text="停止", state="normal", fg=WARN_C)
        if manual:
            self.lbl_scan.configure(
                text=f"全盘扫描中…（深度 {depth}，最多 {int(budget)} 秒；再点「停止」可中断）",
                fg=FG_DIM)

        def work():
            try:
                u, o = adapter.scan_disks(budget=budget, max_depth=depth,
                                          log=self._log,
                                          stop=self._disk_stop.is_set,
                                          first_hit=not manual)
                if u:
                    self.q.put(("scan", (u, o)))
                else:
                    self.q.put(("scanempty", o))
            except Exception as e:
                self.q.put(("err", f"{type(e).__name__}: {e}"))
            finally:
                self.q.put(("scanend", False))

        threading.Thread(target=work, daemon=True).start()

    def _do_disk_scan(self):
        self._start_scan(180.0, 8, manual=True)

    def _do_edl(self):
        """
        从 9008 下载模式只读 boot 分区 —— 不需要 root，也不需要任何外部固件包。

        为什么这条路值得放在界面上：设备没 root 时，boot 分区是 root:root 0600，
        adb shell 拿不到；网上又没有 leaf5 的 OTA 包。剩下唯一的口子是
        Sahara/Firehose：设备进 9008 后 Android 根本没启动，权限模型不在场，
        主机加载 programmer 就能按 GPT 表读分区。

        槽位不用猜：先读 slot_suffix（运行时事实），读不到再用 GPT 的 Active 标志。
        读错槽 = 偏移全错 = 内核崩，所以这一步必须自动。
        """
        if self.busy:
            return
        self._set_busy(True)
        self.btn_edl.configure(state="disabled")
        self.lbl_scan.configure(
            text="正在让设备进 9008（会黑屏重启，属正常）…", fg=FG_DIM)
        self._append("\n[·] EDL 读 boot 分区（只读，不需要 root）")

        def work():
            try:
                import edlman
                out = os.path.join(adapter.work_repo(), "edl_dump")
                d = edlman.dump_boot(out, log=self._log)
                self.q.put(("edl", d))
            except Exception as e:
                self.q.put(("err", f"{type(e).__name__}: {e}"))
            finally:
                self.q.put(("edlend", True))

        threading.Thread(target=work, daemon=True).start()

    def _do_fp(self):
        """
        无 root 读设备指纹。这一步只回答"认不认得出来"，不动设备。

        为什么值得单独一个按钮：设备没 root 时唯一能拿的是
        /proc/kallsyms 的符号名序列（地址被清零，名字完整）。
        这一份序列就足以判断"这台机器是不是我们适配过的那一次构建"，
        判断完再决定要不要动手，避免拿着不对的偏移去 panic。
        """
        if self.busy:
            return
        self._set_busy(True)
        self.lbl_fp.configure(text="正在读设备指纹（全程不用 root）…", fg=FG_DIM)
        self._append("\n[·] 读取设备指纹（/proc/version + /proc/kallsyms 符号名）")

        def work():
            try:
                import fp as fpmod
                f = fpmod.collect(log=self._log)
                path = fpmod.save(f)
                self._log(f"  指纹包 {path}", "dim")
                res = fpmod.match(f, adapter.list_targets())
                self.q.put(("fp", (f, res)))
            except Exception as e:
                self.q.put(("err", f"{type(e).__name__}: {e}"))
            finally:
                self.q.put(("fpend", True))

        threading.Thread(target=work, daemon=True).start()

    def _do_kallsyms(self):
        """
        从连着 USB 的设备上现场导出 /proc/kallsyms。

        这条路成立的前提：target.h 里每个宏都是「符号地址 − _text」的差值，
        差值与 KASLR 无关、与有没有 vmlinux 无关。所以设备能 root，
        就完全不需要固件包里的 ELF。
        """
        if self.busy:
            return
        self._set_busy(True)
        self.lbl_scan.configure(text="正在从设备导出 /proc/kallsyms…", fg=FG_DIM)
        self._append("\n[·] 从设备读取 /proc/kallsyms（需要 su 授权）")

        def work():
            try:
                out = os.path.join(
                    adapter.work_repo(), "kallsyms-%s.txt"
                    % time.strftime("%Y%m%d-%H%M%S"))
                os.makedirs(os.path.dirname(out), exist_ok=True)
                path, st = adapter.grab_kallsyms(out, log=self._log)
                self.q.put(("ksyms", (path, st)))
            except Exception as e:
                self.q.put(("err", f"{type(e).__name__}: {e}"))
            finally:
                self.q.put(("ksymsend", True))

        threading.Thread(target=work, daemon=True).start()

    def _on_scan_empty(self, others):
        self.others = others or []
        self.btn_cand.configure(state="disabled", text="候选", fg=FG_DIM)
        if self.others:
            self.btn_cand.configure(
                state="normal", fg=FG, text=f"候选 0+{len(self.others)}")
            self.lbl_scan.configure(
                text=f"全机没找到能用的内核。{len(self.others)} 个镜像都解不出来，"
                     f"点「候选」看清单。设备上的 boot 分区镜像（或厂商固件包里的"
                     f" boot.img）拖进来就能用，不需要 root",
                fg=WARN_C)
        else:
            self.lbl_scan.configure(
                text="全机都没有可用的内核。两条路都行：把设备上的 boot 分区镜像"
                     "（boot.img / 裸 Image）拖进来现场反解符号表；"
                     "或手机插 USB 点「从设备读符号」直接拉 /proc/kallsyms",
                fg=WARN_C)

    # ------------------------------------------------------------------
    # ① 选文件
    # ------------------------------------------------------------------
    def _browse(self):
        p = filedialog.askopenfilename(
            title="选择 vmlinux.elf、kallsyms 导出文件或 boot.img",
            filetypes=[("符号来源", "*.elf *.txt *.map *.img *.bin"),
                       ("vmlinux.elf", "*.elf"),
                       ("kallsyms / System.map", "*.txt *.map"),
                       ("boot.img", "*.img"),
                       ("全部文件", "*.*")])
        if not p:
            return
        info = adapter.probe_kernel(p)
        if info and info["usable"]:
            self._take(p)
            self.lbl_scan.configure(
                text=f"已选：{os.path.basename(p)}"
                     f"（{adapter.human_size(info['size'])}，{info['note']}）",
                fg=OK_C)
            return
        # 不可用的也填进去（用户可能是想走 boot.img 那条），但说清后果
        self._take(p, remember=False)
        if info:
            self.lbl_scan.configure(
                text=f"已选：{os.path.basename(p)}　{info['note']}", fg=WARN_C)
        else:
            self.lbl_scan.configure(
                text=f"已选：{os.path.basename(p)}　不是内核镜像（既非 ELF 也非 boot.img）",
                fg=BAD_C)

    def _src(self):
        p = self.ent_src.get().strip().strip('"')
        if not p or not os.path.isfile(p):
            raise adapter.AdapterError("先选一个存在的 boot.img 或 vmlinux.elf")
        return p

    # ------------------------------------------------------------------
    # ③ 解 vmlinux
    # ------------------------------------------------------------------
    def _do_unpack(self):
        def work():
            src = self._src()
            with open(src, "rb") as f:
                head = f.read(8)
            if head[:4] == b"\x7fELF":
                self._log(f"输入本身就是 ELF，跳过解压：{src}")
                self.elf_path = src
                self.q.put(("state", "已就绪"))
                return
            if head != b"ANDROID!":
                raise adapter.AdapterError(
                    "既不是 boot.img（缺 ANDROID! 魔数）也不是 ELF。"
                    "如果这是 .bin 或者固件包，先解出 boot.img")

            repo = adapter.ensure_src(log=self._log)
            out = os.path.join(os.path.dirname(repo), "out", "vmlinux.elf")
            os.makedirs(os.path.dirname(out), exist_ok=True)
            self._log(f"从 {os.path.basename(src)} 解出内核…")
            path, kind = adapter.vmlinux_from_boot(src, out, log=self._log)
            self.elf_path = path
            self._log(f"OK  {path}  ({os.path.getsize(path) // 1024} KB, {kind})", "ok")
        self._run(work, "解出 vmlinux")

    # ------------------------------------------------------------------
    # ④ 生成 target.h
    # ------------------------------------------------------------------
    def _do_gen(self):
        def work():
            # 以输入框为准：自动填入之后用户可能又换了文件，不能还拿旧的路径
            src = self.ent_src.get().strip().strip('"')
            if src and os.path.isfile(src):
                info = adapter.probe_kernel(src, deep=False)
                if info and info.get("usable"):
                    self.elf_path = src
            if not self.elf_path:
                raise adapter.AdapterError(
                    "先选一份内核来源：boot.img、裸 ARM64 Image、vmlinux.elf、"
                    "kallsyms 导出文件都行 —— 前三种的符号表都能就地反解")

            repo = adapter.ensure_src(log=self._log)
            exploit = repo
            tmpl = os.path.join(exploit, "targets", "onyx-leaf5", "target.h")
            if not os.path.isfile(tmpl):
                raise adapter.AdapterError(f"模板缺失：{tmpl}")

            self._log(f"解析符号表 {os.path.basename(self.elf_path)} …")
            # boot.img 在这里切段 + 解压成裸 Image 或 ELF；裸 Image 由
            # elfsyms.open_syms 现场反解 kallsyms。调用方不用区分。
            src, how, banner = adapter.resolve_syms_source(
                self.elf_path, log=self._log)
            if banner:
                self._log(f"  镜像 banner: {banner}", "dim")
            offs, miss = elfsyms.extract_offsets(src, tmpl, log=self._log)
            self._log(f"  提到 {len(offs)} 个符号偏移，"
                      f"{len(miss)} 个宏没有同名符号（多是硬编码槽位）", "dim")

            fp = (self.meta or {}).get("fingerprint", "")
            kv = (self.meta or {}).get("kernel", "")
            tid = adapter.suggest_id(fp, kv or os.path.basename(self.elf_path))
            tdir = os.path.join(exploit, "targets", tid)
            unf, nf, diffs = adapter.build_target_h(
                tmpl, os.path.join(tdir, "target.h"), offs, fp, kv,
                log=self._log, syms_mode="trust")

            self.tdir = tdir
            self.diffs = diffs
            # 把符号序列指纹跟着 target 存下来，以后同一台设备不用 root 就能认出来
            sfp = adapter.write_sym_fp(src, tdir, banner)
            if sfp:
                self._log(f"  符号指纹 {os.path.basename(sfp)} 已存"
                          f"（设备指纹能认出这次构建）", "dim")
            self.q.put(("target", tdir))
            self.q.put(("diffs", diffs))

            if diffs:
                self._log(f"  与模板有 {len(diffs)} 个宏不同 —— 换内核时正常，"
                          f"同版本重编时应为 0", "warn")
            else:
                self._log("  与模板完全一致：这份 vmlinux 就是模板对应的构建", "ok")

            self.q.put(("state", f"已生成 {tid}"))
            self._log(f"\n生成 {os.path.join(tdir, 'target.h')}", "ok")
            self._log("下一步：点「打开 target.h」，把这 4 个占位符按注释填上：", "warn")
            for m, hint in adapter.MANUAL_MACROS:
                self._log(f"  {m}\n      {hint}", "warn")
            self.win.after(0, lambda: self._show_fill_hint(unf))
        self._run(work, "生成 target.h")

    def _show_fill_hint(self, unfilled):
        if not unfilled:
            self.lbl_fill.configure(
                text="模板里没找到待填宏 —— 这个 target.h 结构跟工具预期不符，编译前先核对",
                fg=BAD_C)
            return
        self.lbl_fill.configure(
            text="待填：" + "、".join(unfilled) +
                 "　（点「打开 target.h」，把 /*FILL_ME*/ 换成实际值；"
                 "四个值的取法见日志区）",
            fg=WARN_C)

    def _fill_table(self, diffs):
        self.tbl.configure(state="normal")
        self.tbl.delete("1.0", "end")
        self.tbl.insert("end", f"{'宏':<34}{'模板值':>14}{'本机值':>14}{'差':>12}\n", "hdr")
        self.tbl.insert("end", "-" * 74 + "\n", "hdr")
        if not diffs:
            self.tbl.insert("end", "（没有差异 —— 这份 vmlinux 就是模板对应的构建）\n", "note")
        for macro, o, v in diffs:
            self.tbl.insert("end", f"{macro:<34}{hex(o):>14}{hex(v):>14}"
                                   f"{v - o:>+#12x}\n", "diff")
        self.tbl.configure(state="disabled")

    # ------------------------------------------------------------------
    # ⑤ 编译
    # ------------------------------------------------------------------
    def _do_compile(self):
        def work():
            if not self.tdir:
                raise adapter.AdapterError("先生成 target.h")
            if not self.ndk_cc:
                self._log("NDK 没就绪，先检测/下载…", "warn")
                root, cc = ndkman.install(log=self._log)
                self.ndk_root, self.ndk_cc = root, cc
                self.q.put(("ndk", (root, cc)))

            repo = adapter.ensure_src(log=self._log)
            out = os.path.join(os.path.dirname(repo), "out", "preload_migrated.so")
            os.makedirs(os.path.dirname(out), exist_ok=True)
            self._log("开始编译（约 1 分钟）…")
            so, md5, size = adapter.compile_preload(
                repo, self.tdir, self.ndk_cc, out, log=self._log)
            self.so_path = so
            self.q.put(("so", so))
            self._log(f"OK  {so}  {size} 字节  md5={md5}", "ok")
            if size == 2494504:
                self._log("  尺寸与出厂载荷一致（2494504）—— 结构没跑偏", "dim")
        self._run(work, "编译 preload.so")

    # ------------------------------------------------------------------
    # 装进工具
    # ------------------------------------------------------------------
    def _do_install(self):
        if not self.so_path or not os.path.isfile(self.so_path):
            messagebox.showwarning("还没编译", "先点「⑤ 编译 preload.so」", parent=self.win)
            return

        dev = self._read_device()
        meta = {
            "fingerprint": dev.get("fingerprint", ""),
            "kernel": dev.get("kernel", ""),
            "kernel_size": dev.get("kernel_size"),
            "note": "由适配向导生成",
        }
        tid = os.path.basename(self.tdir) if self.tdir else \
            adapter.suggest_id(meta["fingerprint"], meta["kernel"])
        try:
            d = adapter.install_target(tid, self.so_path, meta)
        except Exception as e:
            messagebox.showerror("装不进去", str(e), parent=self.win)
            return
        self._log(f"\n已装进工具：{d}", "ok")
        self._log(f"  target id = {tid}")
        self._log(f"  指纹 = {meta['fingerprint'] or '（未读到设备）'}")
        self._log("  下次主界面跑 root 时，指纹匹配就自动用这份 preload.so", "dim")
        if self.app and hasattr(self.app, "refresh_targets"):
            try:
                self.app.refresh_targets()
            except Exception:
                pass
        messagebox.showinfo("完成",
                            f"已装进工具：\n{tid}\n\n"
                            f"连接同款固件的设备后，主界面会自动选它。",
                            parent=self.win)

    def _read_device(self):
        """从主窗口的 adb 读设备信息。读不到就返回空 dict，不阻断流程。"""
        out = {}
        try:
            adb = getattr(self.app, "adb", None)
            if not adb:
                return out
            out["fingerprint"] = adb.getprop("ro.build.fingerprint") or ""
            out["kernel"] = adb.shell("uname -r", timeout=6).strip()
            out["model"] = adb.getprop("ro.product.model") or ""
            self.meta = out
        except Exception:
            pass
        return out

    def _open_target(self):
        if not self.tdir:
            messagebox.showinfo("还没生成", "先点「④ 生成 target.h」", parent=self.win)
            return
        p = os.path.join(self.tdir, "target.h")
        if not os.path.isfile(p):
            messagebox.showerror("文件不在", p, parent=self.win)
            return
        try:
            os.startfile(p)          # Windows 用默认编辑器打开
        except Exception as e:
            messagebox.showerror("打不开", f"{e}\n\n路径：{p}", parent=self.win)


def open_window(master, app=None):
    """主窗口调这个"""
    return AdapterWindow(master, app)
