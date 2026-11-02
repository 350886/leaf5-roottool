# -*- coding: utf-8 -*-
"""说明文档与界面的一致性（纯数据，不需要 tkinter）。

  python _test_dump/test_help.py

只查「该说的都说了」—— 文档最常见的坏法不是写错，是加了按钮忘了写。
按钮文案从 roottool.py 源码里刮，不 import 它：import 会拉起 tkinter / adb /
edl 一整串，这个测试要能在任何解释器上跑。
"""
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import helpdoc  # noqa: E402

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(HERE, "roottool.py")

FAIL = []


def chk(ok, msg):
    print("  [%s] %s" % ("ok" if ok else "XX", msg))
    if not ok:
        FAIL.append(msg)


def button_labels():
    """`self._btn_group(row, "一键全自动", self.start_one_click,` 里的文案。

    有换行，所以不能按行匹配。
    """
    src = open(SRC, encoding="utf-8").read()
    return re.findall(r'self\._btn_group\(\s*\w+,\s*"([^"]{2,20})"', src)


def main():
    print("=== 章节结构 ===")
    secs = helpdoc.sections()
    chk(len(secs) >= 8, "章节数 %d" % len(secs))
    for name, body in secs:
        chk(bool(name.strip()), "章节名非空：%r" % name)
        chk(len(body) > 120, "「%s」正文 %d 字" % (name, len(body)))

    print("")
    print("=== 按钮都有对应章节 ===")
    labels = button_labels()
    print("  刮到 %d 个按钮：%s" % (len(labels), "、".join(labels)))
    chk(bool(labels), "从 roottool.py 刮到按钮文案")
    doc = helpdoc.plain()
    missing = [t for t in labels if t not in doc]
    chk(not missing, "没有漏写的按钮（缺：%s）" % ("、".join(missing) or "无"))

    print("")
    print("=== 关键字 ===")
    for word in ("fastbootd", "is-userspace", "init_boot", "unknown command",
                 "CAP_SYS_ADMIN", "9008", "payload.bin"):
        chk(word in doc, "说明里有「%s」" % word)

    print("")
    print("=== 快捷键 ===")
    for key in ("F1", "Ctrl+F", "Ctrl+L", "Ctrl+Q", "Ctrl+D"):
        chk(key in doc, "快捷键 %s 已写进说明" % key)

    print("")
    print("=== 导出文本 ===")
    p1, p2 = helpdoc.plain(), helpdoc.plain()
    chk(p1 == p2, "两次导出内容一致（无时间戳之类会漂的东西）")
    chk(p1.splitlines()[0] == helpdoc.TITLE, "首行是标题 %r" % helpdoc.TITLE)
    chk(len(p1) > 6000, "导出的 txt %d 字" % len(p1))

    print("")
    print("=== 搜索 ===")
    hits = helpdoc.search("fastbootd")
    chk(bool(hits), "搜 fastbootd 命中 %d 处" % len(hits))
    chk(helpdoc.search("FASTBOOTD") == hits, "搜索不分大小写")
    chk(helpdoc.search("") == [], "空词返回空")
    chk(helpdoc.search("   ") == [], "纯空格返回空")
    chk(helpdoc.search("zzz-nothing-here") == [], "没命中返回空")
    for idx, line in hits:
        ok = (0 <= idx < len(secs)
              and 0 <= line < len(secs[idx][1].splitlines()))
        if not ok:
            chk(False, "命中坐标越界：%s" % ((idx, line),))
            break
    else:
        chk(True, "命中坐标都在范围内")

    print("")
    if FAIL:
        print("失败 %d 项：" % len(FAIL))
        for m in FAIL:
            print("  - " + m)
        return 1
    print("全部通过（%d 项）" % (len(secs) * 2 + len(labels) + 7 + 5 + 4 + 7))
    return 0


if __name__ == "__main__":
    sys.exit(main())
