"""
普通版 / 集成版界面差异的回归测试。

判据只有一个：包内有没有 assets/gp_ui.on。这个文件由 build.py 在打包集成版时
塞进去，roottool.py 启动时读一次。所以这里不测 GUI，只测那一个判定函数 ——
GUI 只是照着 GP_ENABLED 决定画不画那一行，判定错了会体现在两个 EXE 上。

跑法：python _test_dump/test_gp_ui.py
"""

import os
import sys
import tempfile

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)

import roottool as R  # noqa: E402

OK = 0
BAD = []


def ck(cond, msg, extra=""):
    global OK
    if cond:
        OK += 1
        print(f"  ok  {msg}")
    else:
        BAD.append(msg)
        print(f"  XX  {msg}" + (f"   <- {extra}" if extra else ""))


print("== 1. 源码模式（没 frozen）一律 True ==")
ck(R.GP_ENABLED is True, "源码跑时 GP_ENABLED 为 True，开发时看得见按钮", R.GP_ENABLED)
ck(R._gp_ui_enabled() is True, "再算一次还是 True（不受之前冻结标记影响）")


print("== 2. frozen 且包里没有标记 -> False ==")
_old_frozen = getattr(sys, "frozen", None)
_old_meipass = getattr(sys, "_MEIPASS", None)
d = tempfile.mkdtemp()
sys.frozen = True
sys._MEIPASS = d
ck(R._gp_ui_enabled() is False, "普通版：无标记 -> 不画那一行")


print("== 3. frozen 且有标记 -> True ==")
os.makedirs(os.path.join(d, "assets"), exist_ok=True)
open(os.path.join(d, "assets", "gp_ui.on"), "w", encoding="ascii").close()
ck(R._gp_ui_enabled() is True, "集成版：有标记 -> 画那一行")


print("== 4. 只看标记，不看 apk 目录 ==")
os.remove(os.path.join(d, "assets", "gp_ui.on"))
os.makedirs(os.path.join(d, "assets", "apk"), exist_ok=True)
open(os.path.join(d, "assets", "apk", "Phonesky.apk"), "wb").write(b"PK\x03\x04")
ck(R._gp_ui_enabled() is False,
   "包里有 apk 但没标记 -> 仍按普通版（用户往 EXE 旁丢 apk 不该改变界面）")


print("== 5. build.gp_flag_file 生成的文件能被判定函数认出来 ==")
import build  # noqa: E402

flag = build.gp_flag_file()
ck(os.path.isfile(flag), "gp_flag_file() 落盘了", flag)
ck(os.path.basename(flag) == "gp_ui.on", "文件名就是 gp_ui.on", flag)
# 模拟 PyInstaller 把它放进 assets/
tgt = os.path.join(d, "assets", "gp_ui.on")
open(tgt, "w", encoding="ascii").close()
ck(R._gp_ui_enabled() is True, "放到 assets/ 下 -> 判定为集成版")


print("== 6. 还原 sys 属性，别污染后面的测试 ==")
if _old_frozen is None:
    del sys.frozen
else:
    sys.frozen = _old_frozen
if _old_meipass is None:
    if hasattr(sys, "_MEIPASS"):
        del sys._MEIPASS
else:
    sys._MEIPASS = _old_meipass
ck(getattr(sys, "frozen", None) == _old_frozen, "frozen 已还原")

print()
print(f"通过 {OK} 项" + (f"，失败 {len(BAD)} 项：{BAD}" if BAD else "，全部通过"))
sys.exit(1 if BAD else 0)
