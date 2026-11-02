"""GUI 适配向导的 headless 冒烟：窗口全程 withdraw，不显示。

跑一遍「④ 生成 target.h」的真实代码路径，验证：
  · AdapterWindow 能构造（控件、主题都装得上）
  · _do_gen 里 pick_identity 的取值落到 target.h 上（kernel 是镜像串、指纹为空）
"""
import os
import sys
import time
import tkinter as tk

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

# 隔离：ensure_src 会把源码铺到 work_repo()，别写进真实用户目录
os.environ["LOCALAPPDATA"] = os.path.join(ROOT, "work_v1test", "gui_la")

import adapter            # noqa: E402
import adapter_ui         # noqa: E402

IMG = "E:/BOOX/firmware/_img/Tab8_2026-06-03_18-47_4.2-rel_0603_095d17272b_update.Image"

root = tk.Tk()
root.withdraw()
w = adapter_ui.AdapterWindow(root, autoscan=False)
w.win.withdraw()                      # 立刻藏起来，别闪
root.update_idletasks()
print("[ok] AdapterWindow 构造完成")

w.ent_src.delete(0, "end")
w.ent_src.insert(0, IMG)
print("[..] 跑 _do_gen（真实解析，约 1-2 分钟）")
t0 = time.time()
w._do_gen()

# 必须进真 mainloop：向导的工作线程会用 after() 往主线程排任务，
# 只 update() 的循环会让 Tcl 判定「main thread is not in main loop」。
def tick():
    done = w.tdir and os.path.isfile(os.path.join(w.tdir, "target.h"))
    if done or time.time() - t0 > 540:
        root.quit()
    else:
        root.after(100, tick)


root.after(100, tick)
root.mainloop()
print("[..] 用时 %.0fs  busy=%s" % (time.time() - t0, w.busy))

if not w.tdir:
    print("[X] 没生成 target")
    try:
        body = w.txt.get("1.0", "end").strip()
        print("--- 向导日志 ---")
        print(body[-2500:])
    except Exception as e:
        print("读日志控件失败:", e)
    root.destroy()
    sys.exit(1)

th = os.path.join(w.tdir, "target.h")
head = open(th, encoding="utf-8").read().splitlines()[:3]
print("[ok] target:", w.tdir)
for line in head:
    print("     " + line)
txt = open(th, encoding="utf-8").read()
import re
m = re.search(r'#define\s+BUILD_FINGERPRINT\s+"([^"]*)"', txt)
print("     BUILD_FINGERPRINT = %r" % (m.group(1) if m else "?"))

ok_kernel = "kernel   : 4.19.157-perf-ge2582afab8ec-dirty" in "\n".join(head)
ok_fp = (m is not None and m.group(1) == "")
print("\n结论: kernel 记镜像串=%s  指纹已清空=%s" % (ok_kernel, ok_fp))

root.destroy()
sys.exit(0 if (ok_kernel and ok_fp) else 2)
