# -*- coding: utf-8 -*-
"""菜单栏与使用说明窗口的冒烟测试（V1）。

  "C:/Users/thelu/AppData/Local/Programs/Python/Python312/python.exe" ^
      E:\\BOOX\\root-tool\\_test_dump\\test_help_ui.py

窗口全程 withdraw，不闪窗、不抢焦点。不连设备：App 建好就 destroy，
300ms 的自动 boot 根本不会触发。
"""
import os
import sys
import tkinter as tk

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import helpdoc  # noqa: E402
import helpwin  # noqa: E402
import roottool as R  # noqa: E402

FAIL = []


def chk(ok, msg):
    print("  [%s] %s" % ("ok" if ok else "XX", msg))
    if not ok:
        FAIL.append(msg)


def walk(menu, depth=0):
    out = []
    end = menu.index("end")
    if end is None:
        return out
    for i in range(end + 1):
        if menu.type(i) == "separator":
            out.append((depth, "——", True))
            continue
        label = menu.entrycget(i, "label")
        if menu.type(i) == "cascade":
            out.append((depth, label, True))
            out += walk(menu.nametowidget(menu.entrycget(i, "menu")), depth + 1)
        else:
            try:
                cmd = menu.entrycget(i, "command")
            except tk.TclError:
                cmd = ""
            out.append((depth, label, bool(cmd)))
    return out


def main():
    root = tk.Tk()
    root.withdraw()
    app = R.App(root, port=5057)
    root.update_idletasks()

    # ---- 1. 菜单栏 ----
    bar = app.menubar
    tops = [bar.entrycget(i, "label") for i in range(bar.index("end") + 1)]
    chk(tops == ["文件", "工具", "帮助"], "三个顶级菜单：%s" % tops)

    items = [(d, t, c) for d, t, c in walk(bar) if d > 0]
    chk(len(items) >= 10, "菜单项数量 %d" % len(items))
    dead = [t for _d, t, c in items if not c and t != "——"]
    chk(not dead, "没有空壳菜单项（%s）" % (dead or "无"))

    labels = [t for _d, t, _c in items]
    for need in ("打开日志目录", "打开备份目录", "导出使用说明…", "退出",
                 "刷新设备", "检测（只读）", "清空日志窗口",
                 "使用说明", "关于"):
        chk(need in labels, "菜单里有「%s」" % need)

    # ---- 2. 清空日志 ----
    app.txt.configure(state="normal")
    app.txt.insert("end", "测试行 1\n测试行 2\n")
    app.txt.configure(state="disabled")
    root.update_idletasks()
    before = app.txt.get("1.0", "end").strip()
    app.act_clear_log()
    after = app.txt.get("1.0", "end").strip()
    chk(bool(before) and after == "", "清空日志：%r → %r" % (before, after))

    # ---- 3. 说明窗口 ----
    hw = helpwin.open_help(root)
    hw.withdraw()                       # 立刻藏起来，不闪
    root.update_idletasks()
    chk(isinstance(hw, helpwin.HelpWindow), "open_help 返回 HelpWindow")
    chk(hw.list.size() == len(helpdoc.sections()),
        "左栏章节数 %d == 文档节数 %d" % (hw.list.size(), len(helpdoc.sections())))
    first = hw.text.get("1.0", "end").strip()
    chk(len(first) > 200, "第一节渲染出 %d 字" % len(first))

    # ---- 4. 换节 ----
    hw.show(4)
    chk(hw.text.get("1.0", "end").strip() != first, "切到第 5 节，正文变了")
    chk(hw.lbl_foot.cget("text").startswith("第 5/"), "底部节号：%s"
        % hw.lbl_foot.cget("text"))

    # ---- 5. 搜索 ----
    hw.var_q.set("fastbootd")
    hw.find_next(1)
    chk("处" in hw.lbl_find.cget("text"), "搜索有结果：%s" % hw.lbl_find.cget("text"))
    chk(bool(hw.text.tag_ranges("hit")), "命中处有高亮")
    i0 = hw._hit_i
    hw.find_next(1)
    chk(hw._hit_i != i0, "回车翻到下一处")

    hw.var_q.set("zzz-绝不存在")
    hw.find_next(1)
    chk(hw.lbl_find.cget("text") == "没有匹配", "无结果时明确说没有匹配")

    # ---- 6. 不叠窗 ----
    hw2 = helpwin.open_help(root)
    chk(hw2 is hw, "再开一次返回同一个窗口（不叠窗）")

    # ---- 7. 关于 ----
    helpwin.open_about(root, app_name=R.APP_NAME, app_ver=R.APP_VER,
                       model=R.TARGET_MODEL, firmware=R.TARGET_FIRMWARE,
                       kernel=R.TARGET_KERNEL)
    root.update_idletasks()
    abouts = [w for w in root.winfo_children()
              if isinstance(w, tk.Toplevel) and w.title().startswith("关于")]
    chk(len(abouts) == 1, "关于窗口能打开")
    for w in abouts:
        w.withdraw()
        w.destroy()

    # ---- 8. 导出（绕开对话框，直接写文件）----
    import tempfile
    tmp = os.path.join(tempfile.gettempdir(), "leaf5_help_smoke.txt")
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(helpdoc.plain())
    chk(os.path.getsize(tmp) > 3000, "导出文本 %d 字节" % os.path.getsize(tmp))
    os.remove(tmp)

    hw.destroy()
    root.update_idletasks()
    root.destroy()

    print("")
    if FAIL:
        print("失败 %d 项：" % len(FAIL))
        for m in FAIL:
            print("  - " + m)
        return 1
    print("全部通过")
    return 0


if __name__ == "__main__":
    sys.exit(main())
