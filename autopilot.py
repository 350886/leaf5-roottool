"""
一键全自动：从一台没 root 的设备，到一份偏移对得上的 preload.so。

为什么需要这一层
================
适配向导是给人看着点的：选文件、点生成、看差异、点编译。四步里每一步
都可能选错，而选错的代价是内核在随机位置崩 —— 手机黑屏重启、数据丢、
用户以为刷坏了。

自动流程的价值不是"少点几下"，是**每一步都用设备自己的数据自证**：

   设备指纹  → 本地有没有现成的载荷（有就直接用，一个字节都不编）
   设备版本  → 镜像里 linux_banner 的 commit 对不对（不对就换槽重抓）
   镜像符号  → 反解 kallsyms 得到 55 个偏移
   镜像代码  → 反汇编推 4 个手工宏（TASK_CRED_OFF / PRCTL_FRAME_TOTAL）

任何一步对不上就停在那一步并说清楚原因，绝不带着"大概对"的偏移往下走。

原料从哪来
==========
网上拿不到这台机器的固件包，所以只有两个来源，都不需要 root：

  ① 9008 下载模式 —— 设备进 EDL 后 Android 根本没启动，SELinux 和 Unix
     权限模型都不在场，主机加载 firehose programmer 就能按 GPT 表读分区。
     这条路 edlman.py 已经封装好，且是**唯一**在完全没 root 时可行的。
  ② 已经有临时 root（比如上一轮 exploit 成功过）—— 直接 dd，快得多。

降级顺序：先试 ②，不行走 ①。两个都不行就是硬约束，报错比瞎猜好。
"""

import os
import re
import shutil
import tempfile
import time

import a64
import adapter
import elfsyms


class PilotError(Exception):
    """流程停下，需要人看一眼。消息本身就是给人读的说明。"""


class PilotStopped(Exception):
    """用户点了停止。"""


# 阶段权重。加起来到 1.0，最后一节留给 root 流程
_W = {
    "wait":   (0.00, 0.03),
    "fp":     (0.03, 0.10),
    "lookup": (0.10, 0.12),
    "boot":   (0.12, 0.38),
    "verify": (0.38, 0.42),
    "target": (0.42, 0.56),
    "build":  (0.56, 0.92),
}


class Pilot(object):
    """
    adb:      roottool.Adb 实例（只用它的 exe/serial/env/shell/pull 几样）
    log:      def(str) -> None
    status:   def(str) -> None
    progress: def(float) -> None
    stop:     def() -> bool，返回 True 表示用户要停
    """

    def __init__(self, adb, log=print, status=None, progress=None,
                 stop=None, workdir=None, allow_edl=True, dev_fp=None):
        self.adb = adb
        self._log = log
        self._status = status or (lambda s: None)
        self._progress = progress or (lambda v: None)
        self._stop = stop or (lambda: False)
        self.workdir = workdir or os.path.join(
            os.environ.get("LOCALAPPDATA") or tempfile.gettempdir(),
            "Leaf5RootTool", "pilot")
        self.allow_edl = bool(allow_edl)

        self.dev = dev_fp or {}   # 指纹包（fp.collect 的返回；外面采过就传进来）
        self._dev_seeded = bool(dev_fp)
        self.slot = ""       # "_a" / "_b"
        self.image = ""      # 本机上的 kernel 镜像路径（boot.img 或裸 Image）
        self.target = None   # 生成好的 target 目录
        self.so = ""         # 编译好的 preload.so
        self.used_cached = False

    # -- 小工具 --------------------------------------------------------------

    def log(self, s=""):
        self._log(s)

    def status(self, s):
        self._status(s)

    def step(self, name, frac=0.0):
        a, b = _W[name]
        self._progress(a + (b - a) * max(0.0, min(1.0, frac)))

    def check(self):
        if self._stop():
            raise PilotStopped()

    def sleep(self, sec, tick=0.5):
        """可中断的等待 —— 用户点停止后不用等满 3 分钟才响应。"""
        end = time.time() + sec
        while time.time() < end:
            self.check()
            time.sleep(min(tick, max(0.0, end - time.time())))

    # -- 1. 等设备 -----------------------------------------------------------

    def wait_device(self, limit=None):
        limit = limit or getattr(self, "wait_limit", 180)
        """
        等一台授权好的设备出现。

        这条必须在最前面：用户点「一键」的时候手机可能还没插、没开 USB 调试、
        或者屏幕上那个「允许 USB 调试」的框还没点。等它，别报错退出。
        """
        self.status("等设备")
        self.log("== 1/7 等设备 ==")
        t0 = time.time()
        last_state = None
        while time.time() - t0 < limit:
            self.check()
            try:
                devs = self.adb.devices()
            except Exception as e:
                self.log(f"  adb devices 失败：{e}")
                devs = []

            for d in devs:
                if d["state"] == "device":
                    if not self.adb.serial:
                        self.adb.serial = d["serial"]
                    self.log(f"  设备在线 {d['serial']}  model={d.get('model') or '?'}")
                    self.step("wait", 1.0)
                    return d
                if d["state"] == "unauthorized" and last_state != "unauthorized":
                    self.log("  [!] 设备已连上但没授权 —— 看手机屏幕，点「允许 USB 调试」")
                    last_state = "unauthorized"
                elif d["state"] == "recovery":
                    self.log("  [!] 设备在 recovery 模式，先正常开机")
                    last_state = "recovery"

            if last_state is None:
                self.step("wait", (time.time() - t0) / max(1, limit))
                left = int(limit - (time.time() - t0))
                if int(time.time() - t0) % 15 < 1:
                    self.log(f"  还没看到设备…（剩 {left}s）插线 / 开「USB 调试」")
            self.sleep(2.0)

        raise PilotError(
            "等了 %d 秒没等到可用的设备。\n"
            "  检查：① 数据线是能传数据的（不是只充电那种）\n"
            "        ② 设置 → 开发者选项 → USB 调试 已打开\n"
            "        ③ 手机上有没有弹「允许 USB 调试」，要选中「一律允许」再点确定\n"
            "        ④ adb 端口跟别的工具撞了？改一下端口再试" % limit)

    # -- 2. 采指纹 -----------------------------------------------------------

    def collect_fp(self):
        """
        读设备指纹。/proc/kallsyms 的地址可能被清零，但**符号名和顺序是完整的**，
        用它算的哈希就是这一版内核二进制的身份，零权限可取。
        """
        self.status("读设备指纹")
        self.log("")
        self.log("== 2/7 读设备指纹（不需要 root）==")
        import fp

        try:
            if self._dev_seeded:
                # 上层已经采过了（部署前那次匹配），12 万行没必要读两遍
                self.log("  复用上一阶段采到的指纹")
            else:
                self.dev = fp.collect(serial=self.adb.serial, adb=self.adb.exe,
                                      log=self.log, env=self.adb.env)
        except Exception as e:
            raise PilotError(
                "读设备指纹失败：%s\n"
                "  这一项读不到就没法判断该用哪份载荷。"
                "换个 USB 口或换根线再试。" % e)

        self.slot = self._slot()
        sym = self.dev.get("sym") or {}
        self.log(f"  内核     {self.dev.get('kernel_ver') or '?'}  "
                 f"build #{self.dev.get('kernel_build_no') or '?'}")
        self.log(f"  符号     {sym.get('kernel_syms') or 0} 个"
                 f"（模块 {sym.get('module_syms') or 0}）"
                 f"  零地址 {sym.get('zeroed') or 0}")
        self.log(f"  序列     {(sym.get('sym_digest') or '?')[:24]}")
        self.log(f"  槽位     {self.slot or '(非 A/B)'}")
        self.step("fp", 1.0)
        return self.dev

    def _slot(self):
        try:
            s = self.adb.getprop("ro.boot.slot_suffix").strip()
            if s in ("_a", "_b"):
                return s
        except Exception:
            pass
        try:
            cmd = self.adb.shell("cat /proc/cmdline", timeout=8)
            m = re.search(r"androidboot\.slot_suffix=(_[ab])", cmd or "")
            if m:
                return m.group(1)
        except Exception:
            pass
        return ""

    # -- 3. 查本地 -----------------------------------------------------------

    def lookup(self):
        """
        本地已有同构建的载荷就直接用 —— 一个字节都不用编，也不用碰 boot 分区。
        这是整条流程里唯一"零风险"的出口，优先走它。
        """
        self.status("查本地载荷")
        self.log("")
        self.log("== 3/7 查本地已适配的载荷 ==")
        import fp

        targets = []
        try:
            targets = adapter.list_targets()
        except Exception as e:
            self.log(f"  [!] 读本地 target 清单失败：{e}")

        if not targets:
            self.log("  本地还没有任何适配过的内核")
            self.step("lookup", 1.0)
            return None

        self.log(f"  本地有 {len(targets)} 份："
                 f"{', '.join(t['id'] for t in targets[:5])}"
                 f"{' …' if len(targets) > 5 else ''}")
        res = fp.match(self.dev, targets)
        self.log(f"  结论 {res['verdict']}：{res['why']}")

        if res["verdict"] != "same_build":
            self.log(f"  {res['advice']}")
            self.step("lookup", 1.0)
            return None

        tid = res["id"]
        so = None
        meta = None
        for t in targets:
            if t["id"] == tid:
                meta = t
                cand = os.path.join(t["dir"], "preload.so")
                if os.path.isfile(cand):
                    so = cand
                break
        if not so:
            self.log(f"  [!] target「{tid}」目录里没有 preload.so（只剩清单），重新适配")
            self.step("lookup", 1.0)
            return None

        self.log(f"  命中 target「{tid}」 → {so}  "
                 f"({os.path.getsize(so) // 1024} KB)")
        self.log("  这份载荷的偏移就是这台机器现在跑的内核 —— 不用重编，直接部署")
        self.used_cached = True
        self.so = so
        self.target = meta
        self.step("lookup", 1.0)
        self._progress(0.92)
        return so

    # -- 4. 取内核镜像 -------------------------------------------------------

    def fetch_boot(self):
        """
        把设备**当前运行槽**的 boot 分区弄到本机。

        两条路，按代价排：
          dd    —— 需要临时 root。20 秒，不重启，最省事
          EDL   —— 9008 下载模式，不需要任何权限，但要重启两次、屏幕会黑
        """
        self.status("取内核镜像")
        self.log("")
        self.log("== 4/7 取当前槽的内核镜像 ==")
        os.makedirs(self.workdir, exist_ok=True)

        if self._try_dd():
            self.step("boot", 1.0)
            return self.image

        if not self.allow_edl:
            raise PilotError(
                "没有 root，EDL 又被关掉了 —— 拿不到 boot 分区就没法适配。\n"
                "  打开 EDL 复用（默认开着），或者先用别的办法把 boot 镜像弄到本机。")

        self.log("  没有 root，走 9008 下载模式（设备会黑屏重启，属正常）")
        self._fetch_via_edl(self.slot or None)
        self.step("boot", 1.0)
        return self.image

    def _try_dd(self):
        """有 su 就直接 dd。成功返回 True。"""
        try:
            out = self.adb.shell("su -c id", timeout=10)
        except Exception:
            out = ""
        if "uid=0" not in (out or ""):
            self.log("  设备上没有可用的 su —— 走 EDL")
            return False

        name = "boot" + (self.slot or "")
        self.log(f"  有 root：直接 dd {name}")
        remote = "/data/local/tmp/_pilot_boot.img"
        cmd = (f"su -c 'dd if=/dev/block/by-name/{name} of={remote} "
               f"bs=1048576 2>/dev/null; echo RC=$?'")
        out = self.adb.shell(cmd, timeout=180)
        if "RC=0" not in (out or ""):
            self.log(f"  [!] dd 失败（{out[-80:] if out else '无输出'}），改走 EDL")
            return False

        local = os.path.join(self.workdir, f"{name}.img")
        try:
            self.adb.pull(remote, local, timeout=600)
        except Exception as e:
            self.log(f"  [!] 拉回失败（{e}），改走 EDL")
            return False
        finally:
            try:
                self.adb.shell(f"rm -f {remote}", timeout=10)
            except Exception:
                pass

        size = os.path.getsize(local)
        self.log(f"  {name}.img  {size} 字节 → {local}")
        if size < 8 * 1024 * 1024:
            self.log("  [!] 文件太小，不像 boot 分区，改走 EDL")
            return False

        self._dd_vbmeta()
        self.image = local
        return True

    def _dd_vbmeta(self):
        """
        有 root 时顺手把 vbmeta 也 dd 一份。

        为什么：改 boot 之后 AVB 校验会失败。这台机器 bootloader 已解锁
        （verifiedbootstate=orange），系统不强制校验，所以 root 本身不需要它；
        但它是"改之前的回滚参照" —— 要恢复原厂完整性时，boot 和 vbmeta
        必须成对，只有 boot 是半套。64 KB，代价可忽略。
        """
        slot = self.slot or ""
        cands = [f"vbmeta{slot}", "vbmeta"] if slot else ["vbmeta", "vbmeta_a"]
        for part in cands:
            remote = f"/data/local/tmp/_pilot_{part}.img"
            cmd = (f"su -c 'dd if=/dev/block/by-name/{part} of={remote} "
                   f"bs=1048576 2>/dev/null; echo RC=$?'")
            try:
                out = self.adb.shell(cmd, timeout=60)
            except Exception as e:
                self.log(f"  [!] vbmeta dd 异常：{e}")
                continue
            if "RC=0" not in (out or ""):
                continue
            local = os.path.join(self.workdir, f"{part}.img")
            try:
                self.adb.pull(remote, local, timeout=120)
                self.log(f"  同时备份 {part}  {os.path.getsize(local)} 字节 → {local}")
                return local
            except Exception as e:
                self.log(f"  [!] vbmeta 拉回失败：{e}")
            finally:
                try:
                    self.adb.shell(f"rm -f {remote}", timeout=10)
                except Exception:
                    pass
        self.log("  [!] vbmeta 没备下来（不影响 root，只是少了回滚参照）")
        return None

    def _fetch_via_edl(self, prefer_slot):
        """走 9008。会 reboot edl → 读分区 → reset 回系统。"""
        import edlman

        env = edlman.env_report() if hasattr(edlman, "env_report") else ""
        if env:
            self.log("  " + env)
        try:
            info = edlman.dump_boot(self.workdir, prefer_slot=prefer_slot,
                                    log=self.log, env=self.adb.env,
                                    serial=self.adb.serial)
        except Exception as e:
            raise PilotError(
                "EDL 读取失败：%s\n"
                "  9008 这条路要三样东西齐：edl 工具、firehose programmer、"
                "WinUSB 驱动绑到 05C6:9008。\n"
                "  先用 `python edlman.py env` 看一眼缺哪个。" % e)

        self.image = info["path"]
        self.log(f"  拿到 {info['partition']}  {info['size']} 字节 → {self.image}")
        # vbmeta 是改 boot 之前的回滚参照，不是 root 必需件
        for nm, v in (info.get("extra") or {}).items():
            self.log(f"  同时备份 {nm}  {v['size']} 字节 → {v['path']}")
        # EDL 结束后设备在重启，后面几步要用 adb，得等它回来
        self._wait_back()

    def _wait_back(self, limit=180):
        self.log("  等设备重启回系统…")
        t0 = time.time()
        while time.time() - t0 < limit:
            self.check()
            try:
                if self.adb.getprop("sys.boot_completed") == "1":
                    self.log(f"  已回系统（{int(time.time() - t0)}s）")
                    return True
            except Exception:
                pass
            self.sleep(3.0)
        self.log("  [!] 3 分钟没等到 boot_completed，继续往下试")
        return False

    # -- 5. 校验镜像身份 -----------------------------------------------------

    def verify_banner(self):
        """
        镜像里的 linux_banner 必须跟设备 /proc/version 是同一个 build。

        为什么这一步不能省：A/B 双分区的机器上，boot_b 经常是上一个固件版本，
        而设备正在跑 boot_a。两份镜像的 build 号可能都是 #38（那只是本地
        make 计数），git commit 却不同，偏移差几百字节 —— 拿错的那份去跑，
        漏洞链在内存里打偏，内核在随机位置崩。

        对不上就换另一个槽再抓一次；两次都对不上就停。
        """
        self.status("校验镜像")
        self.log("")
        self.log("== 5/7 校验镜像身份 ==")

        try:
            dev_ver = self.adb.shell("cat /proc/version", timeout=10)
        except Exception:
            dev_ver = ""
        dev_ver = (dev_ver or "").strip()

        banner = adapter.read_kernel_banner(self.image)
        if not banner:
            raise PilotError(
                "镜像里找不到 linux_banner —— 这文件可能不是完整的内核镜像。\n"
                "  正常 boot.img 的 kernel 段里一定有 'Linux version ' 开头的串。")
        self.log(f"  镜像 {banner[:100]}")
        if dev_ver:
            self.log(f"  设备 {dev_ver[:100]}")

        verdict, why, advice = adapter.banner_match(banner, dev_ver)
        self.log(f"  判定 {verdict}：{why}")
        if verdict == "same":
            self.step("verify", 1.0)
            return banner

        if verdict == "resame":
            self.log("  [i] commit 相同、build 号不同 —— 同源码重编，偏移一致，可以继续")
            self.step("verify", 1.0)
            return banner

        if verdict == "dirty" and dev_ver and banner and \
                _commit_of(banner) and _commit_of(banner) == _commit_of(dev_ver):
            self.log("  [i] 两边都是 -dirty 且 commit 相同 —— 按同一份源码处理")
            self.step("verify", 1.0)
            return banner

        if not dev_ver:
            raise PilotError(
                "读不到设备的 /proc/version，没法确认这份镜像就是设备在跑的那个。\n"
                "  带着未验证的偏移往下跑，成功了是运气，失败了是内核崩。停在这里。")

        # 抓错槽了。换一个槽再来一次（只试一次，避免反复重启）
        other = "_a" if self.slot == "_b" else "_b"
        if self.allow_edl and other in ("_a", "_b"):
            self.log(f"  [!] 这份不是设备正在跑的内核。换 {other} 槽重抓一次")
            self._fetch_via_edl(other)
            banner2 = adapter.read_kernel_banner(self.image)
            v2, why2, _ = adapter.banner_match(banner2 or "", dev_ver)
            self.log(f"  再判 {v2}：{why2}")
            if v2 in ("same", "resame"):
                self.slot = other
                self.step("verify", 1.0)
                return banner2
            self.log(f"  [!] {other} 槽也对不上")

        raise PilotError(
            "两个槽的镜像都不是设备正在跑的那个内核。\n"
            "  %s\n"
            "  设备 /proc/version: %s\n"
            "  最后一次镜像 banner: %s\n"
            "  这可能说明设备已经 OTA 过，而本机拿到的是更早的镜像；"
            "也可能是 dump 时选错了分区。\n"
            "  继续跑会拿到错误偏移，内核必崩 —— 所以停在这里。"
            % (advice, dev_ver[:120], (banner or "")[:120]))

    # -- 6. 生成 target.h ----------------------------------------------------

    def make_target(self):
        """
        反解符号 + 反汇编推手工宏，写出 target.h。

        62 个宏里 55 个能直接从符号表算（符号地址 − _text）。
        剩下 4 个不在符号表里，得从代码里读出来：
          TASK_CRED_OFF     —— commit_creds 里 ldr [current, #cred]
          PRCTL_FRAME_TOTAL —— __arm64_sys_prctl 序言的栈帧累加
          WAITER_LOCAL_OFF  —— struct rt_mutex_waiter 的大小（结构体布局，继承模板）
          PRCTL_WAITER_WORD —— 运行期定标，静态推不出（继承模板，失败时换值重试）
        前两个是真推出来的，后两个是结构体/启发式，所以输出里会分别标注。
        """
        self.status("生成 target.h")
        self.log("")
        self.log("== 6/7 生成 target.h ==")

        repo = adapter.ensure_src(log=self.log)
        tmpl = os.path.join(repo, "targets", "onyx-leaf5", "target.h")
        if not os.path.isfile(tmpl):
            raise PilotError(f"模板不见了：{tmpl}")

        src, how, banner = adapter.resolve_syms_source(self.image, log=self.log)
        if how != "direct":
            self.log(f"  自动解包：{how}")

        offs, miss = elfsyms.extract_offsets(src, tmpl, log=self.log)
        if not offs:
            raise PilotError("一个符号都没解出来 —— 这份镜像的 kallsyms 结构不认识。\n"
                             "  （5.x 之后符号名长度改成变长编码，当前实现只认 4.19 的格式）")
        self.log(f"  符号偏移 {len(offs)} 个，模板里还有 {len(miss)} 个宏没有同名符号")

        manual = self._derive_manual(src, tmpl)
        tid = adapter.suggest_id(self.dev.get("fingerprint") or self.dev.get("build_id"),
                                 self.dev.get("kernel_ver"))
        tdir = os.path.join(repo, "targets", tid)
        unf, nf, diffs = adapter.build_target_h(
            tmpl, os.path.join(tdir, "target.h"), offs,
            self.dev.get("fingerprint") or self.dev.get("build_id") or "",
            self.dev.get("kernel_ver") or "", log=self.log,
            syms_mode="trust", manual_values=manual)

        if unf:
            raise PilotError(
                "target.h 里还有 %d 个宏推不出来，留在占位符状态：%s\n"
                "  这些值静态推不出（要 panic 定标或人工反汇编），硬填一个数字"
                "编出来的载荷会让内核崩。\n"
                "  打开「内核适配向导」，手工填完这几个再编译。"
                % (len(unf), ", ".join(unf)))

        adapter.write_sym_fp(src, tdir, banner)
        self.log(f"  → {tdir}/target.h")
        if diffs:
            self.log(f"  {len(diffs)} 个宏与模板原值不同（换了内核，正常）")
            for macro, o, v in diffs[:6]:
                self.log(f"      {macro:<30} 模板 {o:#x} → 实际 {v:#x} ({v - o:+d})",
                         )
        self.target = {"id": tid, "dir": tdir, "kernel": self.dev.get("kernel_ver")}
        self.step("target", 1.0)
        return tdir

    def _derive_manual(self, src, tmpl):
        """
        推 4 个手工宏。推不出的不填，留给调用方判断。

        只对裸 Image 做反汇编：kallsyms 给的偏移在裸 Image 里就等于文件偏移
        （已实测 linux_banner 两边都是 0x1580018）。ELF 的 vaddr 到文件偏移
        还要过一遍 PT_LOAD，多一层出错的地方，收益又不明确 —— 那条路直接
        继承模板值，并在日志里说明。
        """
        vals = {}
        tmpl_vals = _template_manual(tmpl)
        with open(src, "rb") as f:
            head = f.read(4)

        if head == b"\x7fELF":
            self.log("  [!] 输入是 ELF，不做反汇编推导；4 个手工宏全部继承模板值")
            self.log("      （模板值来自同一 SoC 同一大版本的结构体布局，"
                     "换小版本时基本不变）")
            return dict(tmpl_vals)

        buf = open(src, "rb").read()
        syms = elfsyms.ImageSyms(src).symbols()

        cc = syms.get("commit_creds")
        if cc:
            off, why = a64.derive_task_cred_off(buf, cc[0])
            if off:
                vals["TASK_CRED_OFF"] = off
                self.log(f"  TASK_CRED_OFF     = {off:#x}   ← {why}")
            else:
                self.log(f"  [!] TASK_CRED_OFF 推不出：{why}；继承模板 {tmpl_vals.get('TASK_CRED_OFF', 0):#x}")
        else:
            self.log("  [!] 符号表里没有 commit_creds，TASK_CRED_OFF 继承模板")

        pr = syms.get("__arm64_sys_prctl")
        if pr:
            sz, detail = a64.derive_prctl_frame(buf, pr[0])
            if sz:
                vals["PRCTL_FRAME_TOTAL"] = sz
                self.log(f"  PRCTL_FRAME_TOTAL = {sz:#x}   ← {detail}")
            else:
                self.log(f"  [!] PRCTL_FRAME_TOTAL 推不出：{detail}；继承模板")
        else:
            self.log("  [!] 符号表里没有 __arm64_sys_prctl，PRCTL_FRAME_TOTAL 继承模板")

        # 这两个推不出来，明确继承 + 说清楚为什么
        if "WAITER_LOCAL_OFF" in tmpl_vals:
            vals["WAITER_LOCAL_OFF"] = tmpl_vals["WAITER_LOCAL_OFF"]
            self.log(f"  WAITER_LOCAL_OFF  = {vals['WAITER_LOCAL_OFF']:#x}"
                     f"   ← 继承模板（struct rt_mutex_waiter 大小，由结构体定义决定，"
                     f"同大版本恒定）")
        if "PRCTL_WAITER_WORD_DEFAULT" in tmpl_vals:
            vals["PRCTL_WAITER_WORD_DEFAULT"] = tmpl_vals["PRCTL_WAITER_WORD_DEFAULT"]
            self.log(f"  PRCTL_WAITER_WORD = {vals['PRCTL_WAITER_WORD_DEFAULT']}"
                     f"      ← 继承模板（运行期定标值，静态推不出；"
                     f"跑失败会自动换值重试）")
        return vals

    # -- 7. 编译 -------------------------------------------------------------

    def compile(self):
        self.status("编译 preload.so")
        self.log("")
        self.log("== 7/7 编译 preload.so ==")
        import ndkman

        # find_installed 找不到时返回 (None, None)，不抛异常 —— 别拿 try 兜
        root, cc = ndkman.find_installed(log=self.log)
        if cc:
            self.log(f"  复用本机 NDK：{root}")
        else:
            self.log("  本机没找到 NDK，自动下载（约 700MB，解压 3.6GB）")
            try:
                root, cc = ndkman.install(log=self.log, cancel=self._stop)
            except Exception as e:
                raise PilotError(
                    "拿不到 NDK：%s\n"
                    "  编译 preload.so 必须要有 aarch64 的 clang。两条路：\n"
                    "    ① 装 Android Studio，让它下载 NDK（工具会自动认出来）\n"
                    "    ② 让工具自己下（约 700MB，解压 3.6GB，要留够磁盘）" % e)
        if not cc:
            raise PilotError("NDK 装上了但找不到 clang（安装不完整？删掉重装）")
        self.check()

        out_so = os.path.join(self.workdir, "preload.so")
        try:
            so, md5, size = adapter.compile_preload(
                os.path.join(adapter.work_repo(), "exploit"),
                self.target["dir"], cc, out_so,
                log=self.log, cancel=self._stop)
        except Exception as e:
            raise PilotError("编译失败：%s\n  日志在上面，先看第一条 error。" % e)

        self.log(f"  {size} 字节  md5={md5}")
        # 收进 target 仓库：下次同一台机器（或同一次构建的任何一台）不用重编
        try:
            adapter.install_target(self.target["id"], so, {
                "kernel": self.dev.get("kernel_ver") or "",
                "fingerprint": self.dev.get("fingerprint") or self.dev.get("build_id") or "",
                "sym_digest": (self.dev.get("sym") or {}).get("sym_digest") or "",
                "sym_count": (self.dev.get("sym") or {}).get("kernel_syms") or 0,
                "banner": adapter.read_kernel_banner(self.image) or "",
                "auto": True,
            })
            self.log(f"  已收进 target「{self.target['id']}」，下次直接复用")
        except Exception as e:
            self.log(f"  [!] 收进 target 仓库失败（不影响本次）：{e}")

        self.so = so
        self.step("build", 1.0)
        return so

    # -- 总入口 --------------------------------------------------------------

    def run(self):
        self.wait_device()
        self.collect_fp()

        if self.lookup():
            self.log("")
            self.log("本地已有匹配的载荷，跳过取镜像/生成/编译三步")
            self._progress(0.92)
            return self.result()

        self.fetch_boot()
        self.verify_banner()
        self.make_target()
        self.compile()
        return self.result()

    def result(self):
        return {
            "preload_so": self.so,
            "target": self.target,
            "cached": self.used_cached,
            "kernel_ver": self.dev.get("kernel_ver") or "",
            "slot": self.slot,
            "image": self.image,
            "sym_digest": (self.dev.get("sym") or {}).get("sym_digest") or "",
        }


# ---------------------------------------------------------------------------
# 辅助
# ---------------------------------------------------------------------------
def _template_manual(tmpl):
    """从模板读 4 个手工宏的原值（不能被 FILL_MARK 污染的那种）。"""
    txt = open(tmpl, encoding="utf-8").read()
    out = {}
    for macro, _hint in adapter.MANUAL_MACROS:
        m = re.search(r"^#define\s+" + re.escape(macro) + r"\s+"
                      r"(0[xX][0-9a-fA-F]+|\d+)", txt, re.M)
        if m:
            out[macro] = int(m.group(1), 0)
    return out


def _commit_of(text):
    """从 '4.19.157-perf-g3d47a6619220-dirty' 里抠出 git commit 前缀。"""
    m = re.search(r"-g([0-9a-f]{6,40})", text or "")
    return m.group(1) if m else ""


# ---------------------------------------------------------------------------
# 命令行：不经过界面单独跑一遍，排障用
# ---------------------------------------------------------------------------
def _cli():
    import argparse
    ap = argparse.ArgumentParser(
        description="一键全自动准备匹配当前设备的 preload.so")
    ap.add_argument("--serial", default=None)
    ap.add_argument("--adb", default=None)
    ap.add_argument("--port", type=int, default=5053)
    ap.add_argument("--no-edl", action="store_true", help="禁止走 9008")
    ap.add_argument("--workdir", default=None)
    ap.add_argument("--wait", type=int, default=60,
                    help="等设备上线的最长秒数（默认 60）")
    a = ap.parse_args()

    def emit(s=""):
        print(s, flush=True)

    if a.adb:
        exe = a.adb
    else:
        exe = adapter.adb_path()
        if not exe:
            print("[!] 找不到 adb.exe，用 --adb 指定")
            return 2

    env = dict(os.environ)
    env["ANDROID_ADB_SERVER_PORT"] = str(a.port)

    class _Adb(object):
        """最薄的 adb 壳，够 Pilot 用就行。"""
        def __init__(self):
            self.exe = exe
            self.serial = a.serial
            self.env = env

        def _run(self, args, timeout=30):
            import subprocess
            cmd = [self.exe] + (["-s", self.serial] if self.serial else []) + args
            try:
                p = subprocess.run(cmd, capture_output=True, timeout=timeout, env=env)
                return p.returncode, p.stdout.decode("utf-8", "replace")
            except Exception:
                return 1, ""

        def devices(self):
            rc, out = self._run(["devices", "-l"], 20)
            res = []
            for line in out.splitlines()[1:]:
                p = line.split()
                if len(p) >= 2:
                    res.append({"serial": p[0], "state": p[1], "model": ""})
            return res

        def shell(self, cmd, timeout=20):
            rc, out = self._run(["shell", cmd], timeout)
            return out.strip()

        def getprop(self, k):
            return self.shell(f"getprop {k}", 10)

        def pull(self, remote, local, timeout=600):
            import subprocess
            os.makedirs(os.path.dirname(local) or ".", exist_ok=True)
            cmd = [self.exe] + (["-s", self.serial] if self.serial else []) + ["pull", remote, local]
            subprocess.run(cmd, capture_output=True, timeout=timeout, env=env)

    p = Pilot(_Adb(), log=emit, status=lambda s: emit(f"  [{s}]"),
              stop=lambda: False, workdir=a.workdir, allow_edl=not a.no_edl)
    p.wait_limit = a.wait
    try:
        r = p.run()
    except PilotStopped:
        emit("\n已停止")
        return 3
    except PilotError as e:
        emit(f"\n[停下] {e}")
        return 4
    emit("\n完成")
    emit(f"  preload.so  {r['preload_so']}")
    emit(f"  target      {(r['target'] or {}).get('id')}")
    emit(f"  复用本地    {r['cached']}")
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(_cli())
