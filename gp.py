"""
gp.py —— Google Play 安装 / 启用模块。独立文件，不依赖 roottool.RootWorker。

设计约束（实测得出，别改）：

1) **不写 gms_enable。**
   ONYX 在 framework 层拦商店启动，判据是 MMKV 的 `gms_enable`：
       Constant.DISABLED_PACKAGES = { com.android.vending }
       ActivityManagerHelper.gmsEnabled() -> OnyxMMKVConfigHelper.getBool("gms_enable", false)
       ActivityStarter.executeRequest(): !gmsEnabled() && isDisallow(pkg) -> SecurityException
   但这个值由 ONYX 自己在「设置 -> 添加 Google 账号 -> 验证通过」那一刻写入。
   MMKV 是 mmap 二进制（有文件锁 + CRC），外部硬改要先停 ONYX 进程，
   且 ONYX 升级换 key/换存储就失效，写坏了还会毁掉设备上的配置。
   => 本模块只负责把用户送到那个页面，让 ONYX 自己写。

2) **状态判定用行为，不猜内部状态。**
   商店真起来了 = `topResumedActivity` 是 com.android.vending。
   进程在不算数（闪退也会短暂留下进程），包已装也不算数（装了照样被拦）。

3) **APK 不进 EXE。**
   商店包 64 MB，打进 EXE 体积翻倍。走三级回落：
       显式参数 > <base>/assets/apk/ > <base>/apk/ > <cwd>/apk/ > EXE 同级 apk/
   找到多个取体积最大的（体积最大的那个才是完整包，不是 split）。
"""

import os
import re
import sys
import time

STORE_PKG = "com.android.vending"
GMS_PKG = "com.google.android.gms"
GSF_PKG = "com.google.android.gsf"
STORE_ACT = f"{STORE_PKG}/.AssetBrowserActivity"

# 商店拉起后等多久再读前台。电子墨水屏刷新慢，2.5s 是实测下限，
# 低于这个值会在残余桌面帧上误判成"没起来"。
SETTLE = 3.0

_PKG_RE = re.compile(r"\bu0\s+([A-Za-z0-9_.]+)/")
_FOCUS_RE = re.compile(r"\b([A-Za-z0-9_.]+)/[A-Za-z0-9_.$]+")


class GpError(Exception):
    """安装/启动失败。消息直接给人看，不要包成通用错误。"""


class GpState:
    """一次探测的结果。全部字段来自设备实时读取，没有缓存。"""

    __slots__ = ("store_installed", "store_version", "gms_installed",
                 "gsf_installed", "accounts", "top", "running")

    def __init__(self):
        self.store_installed = False
        self.store_version = ""
        self.gms_installed = False
        self.gsf_installed = False
        self.accounts = []          # ['theluck.blue@gmail.com', ...]
        self.top = ""               # 前台包名
        self.running = False        # 前台是不是商店

    def __repr__(self):
        return (f"GpState(store={self.store_installed}/{self.store_version}, "
                f"gms={self.gms_installed}, gsf={self.gsf_installed}, "
                f"acc={self.accounts}, top={self.top}, running={self.running})")


def _looks_like_store(name):
    n = name.lower()
    return ("vending" in n or "phonesky" in n) and n.endswith(".apk")


def candidate_apks(base_dir=None, explicit=None):
    """
    按优先级列出候选 APK 路径（存在且像商店包）。只扫固定几处，不做全盘 find。

    参数都在外面：base_dir 是工具根目录（EXE 所在或脚本所在），
    explicit 是用户/UI 直接指定的文件。
    """
    out = []
    if explicit:
        if not os.path.isfile(explicit):
            raise GpError(f"指定的 APK 不存在：{explicit}")
        out.append(explicit)

    dirs = []
    if base_dir:
        dirs.append(os.path.join(base_dir, "assets", "apk"))
        dirs.append(os.path.join(base_dir, "apk"))
    dirs.append(os.path.join(os.getcwd(), "apk"))
    if getattr(sys, "frozen", False):
        dirs.append(os.path.join(os.path.dirname(sys.executable), "apk"))

    seen = set(os.path.abspath(p) for p in out)
    for d in dirs:
        try:
            names = os.listdir(d)
        except OSError:
            continue
        for n in names:
            if not _looks_like_store(n):
                continue
            p = os.path.abspath(os.path.join(d, n))
            if p in seen:
                continue
            seen.add(p)
            out.append(p)
    return out


class Gp:
    """
    adb 由外部注入（roottool.Adb 实例）。这样单测可以塞假 adb，
    不需要真机就能把六条分支走一遍。
    """

    def __init__(self, adb, base_dir=None, log=None):
        self.adb = adb
        self.base_dir = base_dir
        self._log = log or (lambda s: None)
        self._apk = None

    # -- 探测 ---------------------------------------------------------------

    def _pkg_installed(self, pkg):
        out = self.adb.shell(f"pm list packages {pkg}")
        return f"package:{pkg}" in out

    def _pkg_version(self, pkg):
        out = self.adb.shell(
            f"dumpsys package {pkg} | grep -m1 versionName")
        m = re.search(r"versionName=(\S+)", out)
        return m.group(1) if m else ""

    def google_accounts(self):
        """
        从 dumpsys account 抽 com.google 类型的账号名。

        这是「ONYX 自己写过 gms_enable」的最强旁证：ONYX 只在账号验证通过后写开关，
        所以有已验证账号 ≈ 开关已开。但仍然以 launch_store() 的实际结果为准。
        """
        out = self.adb.shell("dumpsys account | grep 'type=com.google'")
        names = []
        for line in out.splitlines():
            m = re.search(r"name=([^,}\s]+),\s*type=com\.google", line)
            if m and m.group(1) not in names:
                names.append(m.group(1))
        return names

    def top_activity(self):
        """当前前台包名。取不到返回空串，不抛异常（探测不该中断流程）。"""
        out = self.adb.shell(
            "dumpsys activity activities | grep -m1 topResumedActivity")
        m = _PKG_RE.search(out)
        if m:
            return m.group(1)
        m = _FOCUS_RE.search(out)
        return m.group(1) if m else ""

    def probe(self):
        st = GpState()
        st.store_installed = self._pkg_installed(STORE_PKG)
        if st.store_installed:
            st.store_version = self._pkg_version(STORE_PKG)
        st.gms_installed = self._pkg_installed(GMS_PKG)
        st.gsf_installed = self._pkg_installed(GSF_PKG)
        st.accounts = self.google_accounts()
        st.top = self.top_activity()
        st.running = st.top == STORE_PKG
        return st

    # -- 安装 ---------------------------------------------------------------

    def find_apk(self, explicit=None):
        """三级回落找商店 APK；找不到抛 GpError，带上找过的目录，方便用户自己放对位置。"""
        if self._apk and not explicit and os.path.isfile(self._apk):
            return self._apk
        cands = candidate_apks(self.base_dir, explicit)
        if not cands:
            where = [os.path.join(self.base_dir or ".", "apk"),
                     os.path.join(os.getcwd(), "apk")]
            raise GpError("没找到商店 APK，放到这些目录之一：\n  "
                          + "\n  ".join(where)
                          + "\n文件名含 vending 或 Phonesky，扩展名 .apk")
        # 体积最大的才是完整包；split APK 那几片都只有几 MB
        cands.sort(key=lambda p: os.path.getsize(p), reverse=True)
        self._apk = cands[0]
        self._log(f"APK: {self._apk} ({os.path.getsize(self._apk):,} 字节)")
        return self._apk

    def install(self, apk=None, replace=True, timeout=300):
        """
        adb install。`-r` 覆盖安装；`-d` 允许版本号降级
        （从 44.x 退到 42.x 时没有 -d 会被 INSTALL_FAILED_VERSION_DOWNGRADE 挡）。
        """
        path = apk or self.find_apk()
        args = ["install", "-r", "-d", path]
        if not replace:
            args = ["install", path]
        rc, out, err = self.adb.run(args, timeout=timeout)
        blob = (out or "") + (err or "")
        if "Success" in blob:
            self._log("安装成功")
            return True, blob.strip()
        # 已装且版本相同 -> 换 -r 重试没意义，直接报原文
        self._log("安装失败：" + blob.strip()[:300])
        return False, blob.strip()

    # -- 启用（不写 gms_enable，只把用户送到页面） --------------------------

    def open_account_page(self):
        """
        拉起系统「添加账号」页。

        三档回落，任何一档成功即返回：
          1. ADD_ACCOUNT_SETTINGS + 限定 account_types=com.google（Android 13 支持）
          2. ADD_ACCOUNT_SETTINGS 不限类型（让用户自己点 Google）
          3. com.android.settings 首页（兜底，用户手动找）

        用户在这个页面登录并验证完，ONYX 自己把 gms_enable 置真。
        """
        steps = [
            ("-a android.settings.ADD_ACCOUNT_SETTINGS "
             "--esa account_types com.google", "添加账号页（已限定 Google）"),
            ("-a android.settings.ADD_ACCOUNT_SETTINGS", "添加账号页"),
            ("-n com.android.settings/.Settings", "设置首页"),
        ]
        for args, desc in steps:
            rc, out, err = self.adb.run(["shell", f"am start {args}"], timeout=20)
            blob = (out or "") + (err or "")
            if rc == 0 and "Error" not in blob and "Exception" not in blob:
                self._log(f"已拉起：{desc}")
                return True, desc
        return False, "三档入口都没拉起"

    # -- 验证 ---------------------------------------------------------------

    def launch_store(self, settle=SETTLE):
        """
        真拉起商店并看它有没有留在前台。

        被 ONYX 拦时 am 的 stderr/stdout 里会带
        `SecurityException: This app is not allowed to start because Google Play is disabled.`
        但这条不一定总在 am 的输出里（异常抛在 system_server 侧），
        所以还必须再看一次 topResumedActivity —— 两个判据缺一不可。
        """
        rc, out, err = self.adb.run(["shell", f"am start -W -n {STORE_ACT}"], timeout=30)
        blob = ((out or "") + (err or "")).strip()
        if "SecurityException" in blob or "not allowed to start" in blob:
            return False, "拦", blob
        time.sleep(settle)
        top = self.top_activity()
        return (top == STORE_PKG), top, blob

    def enable(self, apk=None, install_if_missing=True, settle=SETTLE,
               reinstall_if_blocked=False):
        """
        编排：装（缺才装）-> 拉起 -> 不行就引导登录 -> 再拉起。

        reinstall_if_blocked：已装但拉不起来时，用 apk 目录里那个包覆盖重装再试一次。
        默认关（纯探测不该动设备）；UI 里开，因为 44.x 装得上但一开就退，
        手上有 42.x 的包就该直接换上，而不是让人去重登账号。

        返回 dict，字段固定，UI 直接照着渲染：
            {
              "ok": bool,              # 最后商店在不在前台
              "stage": str,            # installed / launched / need_login / blocked / failed
              "detail": str,
              "state": GpState,
              "need_manual": bool,     # True = 需要用户去设备上点登录
            }
        """
        res = {"ok": False, "stage": "", "detail": "", "state": None, "need_manual": False}

        st = self.probe()
        res["state"] = st

        # 1. GMS/GSF 不在就不用往下走了 —— 那要刷固件，本模块管不了
        if not st.gms_installed:
            res.update(stage="failed",
                       detail=f"{GMS_PKG} 不在系统里，这个模块装不了（它得预置在 priv-app）")
            return res

        # 2. 商店本体
        if not st.store_installed:
            if not install_if_missing:
                res.update(stage="failed", detail="商店未安装，且禁止了自动安装")
                return res
            ok, msg = self.install(apk)
            if not ok:
                res.update(stage="failed", detail=f"安装失败：{msg[:300]}")
                return res
            res["stage"] = "installed"
            st = self.probe()
            res["state"] = st

        # 3. 直接拉一次
        running, top, blob = self.launch_store(settle=settle)
        if running:
            res.update(ok=True, stage="launched",
                       detail=f"商店已在运行 {st.store_version}")
            return res

        # 3b. 换成包外那个 APK 再试一次。
        #     实测 44.6.15 在 Leaf5 上装得上、一开就退；42.0.18-31 正常。
        #     这里有包就换，比让人去猜"为什么有账号还是 blocked"省事得多。
        if reinstall_if_blocked:
            try:
                cand = self.find_apk(apk)
            except GpError:
                cand = None
            if cand:
                ok, msg = self.install(cand)
                if ok:
                    running, top, blob = self.launch_store(settle=settle)
                    if running:
                        newst = self.probe()
                        res["state"] = newst
                        res.update(ok=True, stage="launched",
                                   detail=f"用 {os.path.basename(cand)} 覆盖重装后起来了"
                                          f"（{newst.store_version}）")
                        return res
                    gone = ("\n覆盖重装也没起来，前台是 " + (top or "未知"))
                else:
                    gone = "\n覆盖重装失败：" + msg.strip()[:200]
            else:
                gone = ""
        else:
            gone = ""

        # 4. 拉不起来。已经登录过账号还拉不起来 = 真被拦（或者是别的原因），
        #    没账号 = 缺的正是 ONYX 那一步登录。
        if st.accounts:
            res.update(stage="blocked", need_manual=True,
                       detail=("商店起不来，但 Google 账号已在：" + ", ".join(st.accounts) +
                               "\n前台是 " + (top or "未知") + gone +
                               "\n可能 gms_enable 还没写进去：去 设置 -> 账号 -> 重新登录一次 Google 账号完成验证"))
            return res

        # 5. 没有账号 -> 把用户送到添加账号页
        ok, desc = self.open_account_page()
        if not ok:
            res.update(stage="blocked", need_manual=True,
                       detail="没账号，也没拉起添加账号页。手动去：设置 -> 账号 -> 添加账号 -> Google")
            return res

        res.update(stage="need_login", need_manual=True,
                   detail=(f"已打开「{desc}」。在设备上添加 Google 账号并完成验证，"
                           f"完成后点「重新检测」"))
        return res
