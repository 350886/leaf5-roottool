"""
gp.py 的分支测试。不连真机：用 FakeAdb 顶替 adb，把六条路径各走一遍。

跑：
    cd root-tool && python _test_dump/test_gp.py
"""

import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import gp  # noqa: E402

OK = 0
BAD = []


def ck(cond, label, extra=""):
    global OK
    if cond:
        OK += 1
        print(f"  PASS  {label}")
    else:
        BAD.append(label)
        print(f"  FAIL  {label}  {extra}")


class FakeAdb:
    """
    按命令内容分派。字段直接对应设备上的返回值，
    测试只关心「给这些返回值，分支走不走对」。
    """

    def __init__(self, packages=(), versions=None, accounts=(),
                 store_top="com.android.vending", launch_raises=False,
                 install_ok=True, account_page_ok=True):
        self.packages = set(packages)
        self.versions = versions or {}
        self.accounts = list(accounts)
        self.store_top = store_top
        self.launch_raises = launch_raises
        self.install_ok = install_ok
        self.account_page_ok = account_page_ok
        self.calls = []

    # roottool.Adb 的两个方法
    def shell(self, cmd, timeout=20):
        self.calls.append(("shell", cmd))
        if cmd.startswith("pm list packages"):
            pkg = cmd.split()[-1]
            return f"package:{pkg}\n" if pkg in self.packages else ""
        if cmd.startswith("dumpsys package"):
            pkg = cmd.split()[2]
            v = self.versions.get(pkg)
            return f"    versionName={v}\n" if v else ""
        if cmd.startswith("dumpsys account"):
            if not self.accounts:
                return ""
            return "".join(
                f"    Account {{name={a}, type=com.google}}\n" for a in self.accounts)
        if cmd.startswith("dumpsys activity activities"):
            if not self.store_top:
                return ""
            return (f"  topResumedActivity=ActivityRecord{{9f2a1c3 u0 "
                    f"{self.store_top}/com.google.android.finsky.activities.MainActivity t77}}\n")
        return ""

    def run(self, args, timeout=20):
        self.calls.append(("run", list(args)))
        if args[0] == "install":
            if self.install_ok:
                return 0, "Performing Streamed Install\nSuccess\n", ""
            return 1, "", "Failure [INSTALL_FAILED_VERSION_DOWNGRADE]\n"
        if args[0] == "shell":
            cmd = args[1]
            if "am start" in cmd:
                if "vending" in cmd and self.launch_raises:
                    return 0, ("Starting: Intent { cmp=com.android.vending/.AssetBrowserActivity }\n"
                               "Error: java.lang.SecurityException: This app is not allowed to "
                               "start because Google Play is disabled.\n"), ""
                if "ADD_ACCOUNT_SETTINGS" in cmd or "settings" in cmd:
                    if self.account_page_ok:
                        return 0, "Starting: Intent { act=android.settings.ADD_ACCOUNT_SETTINGS }\n", ""
                    return 1, "", "Error: Activity not started\n"
                return 0, "Starting: Intent { }\n", ""
        return 0, "", ""


def new_gp(adb, base=None):
    return gp.Gp(adb, base_dir=base, log=lambda s: None)


print("== 1. GMS 不在 ==")
adb = FakeAdb(packages={gp.STORE_PKG}, versions={gp.STORE_PKG: "42.0.18-31"})
r = new_gp(adb).enable(settle=0)
ck(r["stage"] == "failed", "stage=failed", r)
ck("GMS" in r["detail"] or gp.GMS_PKG in r["detail"], "detail 提到缺 GMS", r["detail"])
ck(not r["ok"], "ok=False")

print("== 2. 商店未装 + 禁止自动装 ==")
adb = FakeAdb(packages={gp.GMS_PKG, gp.GSF_PKG})
r = new_gp(adb, base=tempfile.mkdtemp()).enable(settle=0, install_if_missing=False)
ck(r["stage"] == "failed", "stage=failed", r)
ck("未安装" in r["detail"], "detail 说明未安装", r["detail"])

print("== 3. 商店未装 -> 装 -> 拉起成功 ==")
d = tempfile.mkdtemp()
os.makedirs(os.path.join(d, "apk"))
apk = os.path.join(d, "apk", "Phonesky_42.0.18-31.apk")
open(apk, "wb").write(b"x" * 4096)
adb = FakeAdb(packages={gp.GMS_PKG, gp.GSF_PKG},
              versions={gp.STORE_PKG: "42.0.18-31"})
g = new_gp(adb, base=d)
# 装完之后 pm list packages 才会返回真值，这里模拟这个状态转移
orig_run = adb.run
def run_after_install(args, timeout=20):
    out = orig_run(args, timeout)
    if args[0] == "install":
        adb.packages.add(gp.STORE_PKG)
    return out
adb.run = run_after_install
r = g.enable(settle=0)
ck(r["ok"] and r["stage"] == "launched", "装完拉起 -> ok/launched", r)
ck(any(c[0] == "run" and c[1][0] == "install" for c in adb.calls), "确实调了 install")

print("== 4. 已装 + 被 SecurityException 拦 + 有账号 ==")
adb = FakeAdb(packages={gp.STORE_PKG, gp.GMS_PKG, gp.GSF_PKG},
              versions={gp.STORE_PKG: "42.0.18-31"},
              accounts=["theluck.blue@gmail.com"],
              store_top="com.android.launcher3", launch_raises=True)
r = new_gp(adb).enable(settle=0)
ck(r["stage"] == "blocked", "stage=blocked", r)
ck(r["need_manual"] is True, "need_manual=True")
ck("theluck.blue@gmail.com" in r["detail"], "detail 带上账号名", r["detail"])
ck(not r["ok"], "ok=False")

print("== 5. 已装 + 没起来 + 没账号 -> 拉账号页 ==")
adb = FakeAdb(packages={gp.STORE_PKG, gp.GMS_PKG, gp.GSF_PKG},
              versions={gp.STORE_PKG: "42.0.18-31"},
              store_top="com.android.launcher3")
r = new_gp(adb).enable(settle=0)
ck(r["stage"] == "need_login", "stage=need_login", r)
ck(r["need_manual"] is True, "need_manual=True")
ck("添加账号" in r["detail"] or "账号" in r["detail"], "detail 指向账号页", r["detail"])

print("== 6. 没账号 且 账号页也拉不起 ==")
adb = FakeAdb(packages={gp.STORE_PKG, gp.GMS_PKG, gp.GSF_PKG},
              versions={gp.STORE_PKG: "42.0.18-31"},
              store_top="com.android.launcher3", account_page_ok=False)
r = new_gp(adb).enable(settle=0)
ck(r["stage"] == "blocked", "stage=blocked", r)
ck("手动" in r["detail"], "detail 给出手动路径", r["detail"])

print("== 7. 已装 + 直接起来 ==")
adb = FakeAdb(packages={gp.STORE_PKG, gp.GMS_PKG, gp.GSF_PKG},
              versions={gp.STORE_PKG: "42.0.18-31"})
r = new_gp(adb).enable(settle=0)
ck(r["ok"] and r["stage"] == "launched", "ok/launched", r)
ck("42.0.18-31" in r["detail"], "detail 带版本号", r["detail"])

print("== 8. 安装失败 ==")
d = tempfile.mkdtemp()
os.makedirs(os.path.join(d, "apk"))
open(os.path.join(d, "apk", "vending_big.apk"), "wb").write(b"x" * 8192)
adb = FakeAdb(packages={gp.GMS_PKG, gp.GSF_PKG}, install_ok=False)
r = new_gp(adb, base=d).enable(settle=0)
ck(r["stage"] == "failed", "stage=failed", r)
ck("VERSION_DOWNGRADE" in r["detail"], "detail 带原始失败原因", r["detail"])

print("== 9. candidate_apks 取体积最大的 ==")
d = tempfile.mkdtemp()
os.makedirs(os.path.join(d, "assets", "apk"))
os.makedirs(os.path.join(d, "apk"))
open(os.path.join(d, "assets", "apk", "Phonesky.apk"), "wb").write(b"x" * 1024)
big = os.path.join(d, "apk", "com.android.vending_42.apk")
open(big, "wb").write(b"x" * 65536)
open(os.path.join(d, "apk", "readme.txt"), "wb").write(b"x" * 999999)
got = gp.candidate_apks(base_dir=d)
ck(len(got) == 2, f"筛掉非 apk，剩 {len(got)} 个", got)
g = new_gp(FakeAdb(), base=d)
ck(g.find_apk() == big, "取体积最大的那个", g.find_apk())
try:
    gp.candidate_apks(base_dir=d, explicit="/no/such.apk")
    ck(False, "显式指定的 APK 不存在时应抛 GpError")
except gp.GpError as e:
    ck("/no/such.apk" in str(e), "显式路径不存在 -> GpError 带上路径", str(e))

print("== 10. top_activity 两种格式 ==")
a1 = FakeAdb(store_top="com.android.vending")
ck(new_gp(a1).top_activity() == "com.android.vending", "u0 格式")
class NoU0(FakeAdb):
    def shell(self, cmd, timeout=20):
        return "  topResumedActivity=ActivityRecord{abc com.android.launcher3/.Launcher t1}\n"
ck(new_gp(NoU0()).top_activity() == "com.android.launcher3", "无 u0 回落到通用正则")

print("== 11. google_accounts 去重 ==")
a = FakeAdb(accounts=["a@gmail.com", "b@gmail.com", "a@gmail.com"])
acc = new_gp(a).google_accounts()
ck(acc == ["a@gmail.com", "b@gmail.com"], f"去重 {acc}")

print("== 12. GMS 在但商店装在 ==")
adb = FakeAdb(packages={gp.GMS_PKG}, versions={gp.STORE_PKG: "42.0.18-31"},
              store_top="com.android.vending")
# 只装 GMS、没装商店 -> 走 install，但目录里没 apk -> GpError
g = new_gp(adb, base=tempfile.mkdtemp())
try:
    g.enable(settle=0)
    ck(False, "没 APK 时应抛 GpError")
except gp.GpError as e:
    ck("放到这些目录" in str(e), "GpError 给出放置目录", str(e))

print("== 13. 已装但起不来 + 手上有包 -> 覆盖重装后起来了 ==")
d = tempfile.mkdtemp()
os.makedirs(os.path.join(d, "apk"))
open(os.path.join(d, "apk", "Phonesky_42.0.18-31.apk"), "wb").write(b"x" * 4096)
adb = FakeAdb(packages={gp.STORE_PKG, gp.GMS_PKG, gp.GSF_PKG},
              versions={gp.STORE_PKG: "44.6.15"},
              accounts=["theluck.blue@gmail.com"],
              store_top="com.android.launcher3")
_orig = adb.run
def run_fix(args, timeout=20):
    out = _orig(args, timeout)
    if args[0] == "install":
        # 装回 42.x 之后商店就能起来了
        adb.store_top = gp.STORE_PKG
        adb.versions[gp.STORE_PKG] = "42.0.18-31"
    return out
adb.run = run_fix
r = new_gp(adb, base=d).enable(settle=0, reinstall_if_blocked=True)
ck(r["ok"] and r["stage"] == "launched", "重装后 launched", r)
ck("覆盖重装" in r["detail"], "detail 说明是重装救回来的", r["detail"])
ck("42.0.18-31" in r["detail"], "detail 带重装后的版本", r["detail"])

print("== 14. 同一场景但不开 reinstall -> 保持 blocked ==")
adb = FakeAdb(packages={gp.STORE_PKG, gp.GMS_PKG, gp.GSF_PKG},
              versions={gp.STORE_PKG: "44.6.15"},
              accounts=["theluck.blue@gmail.com"],
              store_top="com.android.launcher3")
r = new_gp(adb, base=d).enable(settle=0)
ck(r["stage"] == "blocked", "不开重装 -> blocked", r)
ck(not any(c[0] == "run" and c[1][0] == "install" for c in adb.calls),
   "一个 install 都没调")

print("== 15. 重装也失败 -> detail 带上失败原因 ==")
d2 = tempfile.mkdtemp()
os.makedirs(os.path.join(d2, "apk"))
open(os.path.join(d2, "apk", "vending.apk"), "wb").write(b"x" * 4096)
adb = FakeAdb(packages={gp.STORE_PKG, gp.GMS_PKG, gp.GSF_PKG},
              versions={gp.STORE_PKG: "42.0.18-31"},
              accounts=["a@gmail.com"],
              store_top="com.android.launcher3", install_ok=False)
r = new_gp(adb, base=d2).enable(settle=0, reinstall_if_blocked=True)
ck(r["stage"] == "blocked", "仍是 blocked", r)
ck("覆盖重装失败" in r["detail"], "detail 带重装失败原因", r["detail"])

print()
print(f"通过 {OK} 项" + (f"，失败 {len(BAD)} 项：{BAD}" if BAD else "，全部通过"))
sys.exit(1 if BAD else 0)
