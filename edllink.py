# -*- coding: utf-8 -*-
"""
edlcore —— 把 bkerler/edl 当库用，在单进程内完成 9008 通信。

两个设计决定，先说清为什么：

1) 不用子进程。
   打成单文件 EXE 之后 sys.executable 就是 EXE 自己，再启动一次只会重跑 GUI，
   不会跑 edl.py。所以 edl 必须在本进程内执行。

   能不能这么干取决于 edl.py 自己：main.__init__(args, imported) 里若 imported
   非空，exit() 只 return 不 sys.exit（edl.py:244-251）。这是它留好的库化入口。

2) sys.stdout 上挂一个常驻转发器，而不是每次调用换对象。
   edlclient 的 LogBase 是 metaclass，每次 main() 实例化都会 logging.config.
   dictConfig 重建 handler，handler 的 stream 写的是 "ext://sys.stdout" ——
   解析时刻就是 dictConfig 执行的那一刻。如果每次调用都塞新对象，模块级那次
   初始化创建的 handler 会一直指着旧对象，日志就漏了。
   所以：进程内第一次 import 之前就把 sys.stdout 换成 _Router，此后只换
   _Router.target，谁什么时候抓 stream 都抓到同一个壳子。
"""

import os
import re
import sys
import threading
import time

# ----------------------------------------------------------------------
# 资源定位
# ----------------------------------------------------------------------
def res_dir():
    """EXE 里是解包根目录，源码里是本文件所在目录。"""
    if getattr(sys, "frozen", False):
        return getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(sys.executable)))
    return os.path.dirname(os.path.abspath(__file__))


def assets_dir():
    return os.path.join(res_dir(), "assets")


def _loader_dirs():
    """
    programmer 可能在哪。打包后在 _MEIPASS/assets；源码模式在
    脚本目录/assets、脚本目录/loaders、上一级/loaders（项目里 loaders 和
    root-tool 是平级的，不能只看 assets）。
    """
    out = [assets_dir(), os.path.join(res_dir(), "loaders"),
           os.path.join(os.path.dirname(res_dir()), "loaders")]
    env = os.environ.get("LEAF5_EDL_LOADER_DIR")
    if env:
        out.insert(0, env)
    return out


def loader_candidates():
    """
    firehose programmer。lito 平台两个都留：
      lito_op_n10_fhprg.bin   OnePlus N10（SM6350，实测通过的那份，排第一）
      lito_moto_fhprg.bin     摩托罗拉同平台，互为备份
    """
    out = []
    for d in _loader_dirs():
        for n in ("lito_op_n10_fhprg.bin", "lito_moto_fhprg.bin"):
            p = os.path.join(d, n)
            if os.path.isfile(p) and p not in out:
                out.append(p)
    # 兜底：任何 *_fhprg.bin
    for d in _loader_dirs():
        if not os.path.isdir(d):
            continue
        for n in sorted(os.listdir(d)):
            p = os.path.join(d, n)
            if n.lower().endswith("_fhprg.bin") and p not in out:
                out.append(p)
    return out


def loader_path():
    ls = loader_candidates()
    return ls[0] if ls else None


# ----------------------------------------------------------------------
# 输出捕获
# ----------------------------------------------------------------------
ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
# edl 的进度行形状：(Sector 0x1F40 of 0x30000, 02s left) 12.34 MB/s
PROG_RE = re.compile(r"Sector\s+0x([0-9A-Fa-f]+)\s+of\s+0x([0-9A-Fa-f]+)")


class _Router:
    """
    常驻 sys.stdout / sys.stderr 替身。target 为空时静默吞掉。

    为什么 target 为空也要吞：GUI 模式（--windowed）没有控制台，fd 1 无效，
    任何 print 都会炸出 "lost sys.stdout" 之类的异常，而 edl 里 print 遍地都是。
    """

    encoding = "utf-8"
    errors = "replace"

    def __init__(self):
        self.target = None

    def write(self, s):
        t = self.target
        if t is None:
            return len(s)
        try:
            return t.write(s)
        except Exception:
            return len(s)

    def flush(self):
        t = self.target
        if t is not None:
            try:
                t.flush()
            except Exception:
                pass

    def isatty(self):
        return False

    def fileno(self):
        # tqdm 之类会探测；没有真 fd，抛出去让它们走 fallback 分支
        raise OSError("no fileno")


ROUTER = _Router()
# 回调里的 print 在 GUI 模式（根本没有 stdout）落到这里，防止绕回 ROUTER
_DEVNULL = open(os.devnull, "w")


class _Sink:
    """
    行切分器。edl 的进度条用 \\r 原地覆盖，所以 \\r 和 \\n 都算行边界。
    """

    def __init__(self, on_line, on_progress, real_out=None):
        self.on_line = on_line
        self.on_progress = on_progress
        self.real_out = real_out     # 回调里 print 应该落到哪儿（见 _emit）
        self.buf = ""
        self.lock = threading.Lock()
        self.last_prog = -1.0
        # 这些是每次都会出现的启动噪音，不往日志窗口里塞
        self.mute = (
            "Keystone library is missing",
            "No module named 'Cryptodome'",
            "No module named 'keystone'",
        )

    def write(self, s):
        if not s:
            return 0
        with self.lock:
            self.buf += s
            while True:
                i_n = self.buf.find("\n")
                i_r = self.buf.find("\r")
                if i_n < 0 and i_r < 0:
                    break
                if i_r < 0:
                    i = i_n
                elif i_n < 0:
                    i = i_r
                else:
                    i = min(i_n, i_r)
                line = self.buf[:i]
                self.buf = self.buf[i + 1:]
                self._emit(line)
        return len(s)

    def _emit(self, line):
        line = ANSI_RE.sub("", line).rstrip()
        if not line.strip():
            return
        # edl 在等设备时每轮打一个 "."，进日志窗口就是一屏点，没信息量
        st = line.strip()
        if st and set(st) == {"."}:
            return
        for m in self.mute:
            if m in line:
                return
        pg = PROG_RE.search(line)
        if pg:
            pos = int(pg.group(1), 16)
            tot = int(pg.group(2), 16)
            frac = (pos / tot) if tot else 0.0
            # 只按 1% 粒度回调，否则 30000 扇区能打出上万次 UI 更新
            if frac - self.last_prog >= 0.01 or frac >= 1.0:
                self.last_prog = frac
                if self.on_progress:
                    self.on_progress(min(frac, 1.0), line)
            return
        if self.on_line:
            # 回调里普遍写成 `log(t)`，而 CLI 传进来的 log 就是 print。
            # 此刻 sys.stdout 是 ROUTER（正指向本 sink），直接调就会绕回来
            # 无限递归。临时切到真实输出流，让那行 print 落到日志里。
            old = sys.stdout
            if self.real_out is not None:
                sys.stdout = self.real_out
            try:
                self.on_line(line)
            finally:
                sys.stdout = old

    def flush(self):
        if self.buf.strip():
            line, self.buf = self.buf, ""
            self._emit(line)

    def isatty(self):
        return False

    def fileno(self):
        raise OSError("no fileno")


# ----------------------------------------------------------------------
# 启动：装转发器 + import edl
# ----------------------------------------------------------------------
_ready = False
_edlmain = None
_docopt = None
_init_lock = threading.Lock()


def _prepare():
    """幂等初始化。第一次调用时装转发器、注册 libusb DLL、import edl。"""
    global _ready, _edlmain, _docopt, ROUTER
    if _ready:
        return
    with _init_lock:
        if _ready:
            return

        # pyusb 在 Windows 上不会自己找 DLL，必须显式 add_dll_directory。
        # libusb-package 把 libusb-1.0.dll 放在包目录里，跟着 EXE 一起打包。
        try:
            import libusb_package
            d = os.path.dirname(libusb_package.find_library("libusb-1.0"))
            if d:
                try:
                    os.add_dll_directory(d)
                except Exception:
                    pass
                os.environ["PATH"] = d + os.pathsep + os.environ.get("PATH", "")
        except Exception:
            # 找不到 DLL 时不在这里失败：真正连设备时 pyusb 会给出更明确的错
            pass

        if not getattr(sys, "frozen", False):
            here = os.path.dirname(os.path.abspath(__file__))
            if here not in sys.path:
                sys.path.insert(0, here)

        # 挂转发器。必须在 import edlmain 之前：模块顶层会 docopt 一次，
        # LogBase 也会在那时把 handler 绑到 sys.stdout 上。
        old_out, old_err = sys.stdout, sys.stderr
        sys.stdout = ROUTER
        sys.stderr = ROUTER
        argv_bak = sys.argv[:]
        try:
            # edl.py 顶层执行 args = docopt(__doc__)，此刻 argv 必须是它认得的形状
            sys.argv = ["edlmain.py", "printgpt", "--loader=" + (loader_path() or "None")]
            import edlmain as _m
            from docopt import docopt as _d
            _edlmain, _docopt = _m, _d
        finally:
            sys.argv = argv_bak
            sys.stdout = old_out
            sys.stderr = old_err
        _ready = True


class EdlError(Exception):
    pass


class Edl:
    """
    一次 9008 会话。同一个实例串行用；并发调会排队（USB 设备本来就独占）。

    on_line(text)        普通输出行
    on_progress(frac, t) 进度行，frac 0..1
    """

    def __init__(self, loader=None, on_line=None, on_progress=None, timeout=300):
        _prepare()
        self.loader = loader or loader_path()
        self.on_line = on_line
        self.on_progress = on_progress
        self.timeout = timeout
        self._lock = threading.Lock()
        self._poisoned = False          # 超时后为 True，禁止再发起调用
        self.last_output = ""           # 最近一次调用的完整输出，排障用

    # -- 内部 ----------------------------------------------------------
    def _argv(self, cmd, extra=None):
        a = ["edlmain.py", "--loader=" + self.loader.replace("\\", "/"),
             "--memory=eMMC"]
        if extra:
            a += list(extra)
        a += list(cmd)
        return a

    def _call(self, cmd, extra=None, timeout=None):
        """
        跑一条 edl 命令，返回完整输出文本。

        超时处理是硬限制：run() 是阻塞的 USB 读，Python 杀不掉线程。
        所以超时后把实例标记为 poisoned，后续调用一律拒绝 —— 残留线程还握着
        USB 句柄，再发命令会两条线程抢同一个设备，结果是数据错乱而不是报错。
        """
        if self._poisoned:
            raise EdlError("上一次调用超时后设备句柄状态不明，请重启本工具再试。")
        if not self.loader:
            raise EdlError("找不到 firehose programmer（assets\\*_fhprg.bin）。\n"
                           "  这个文件是程序自带的，缺了说明解包不完整，重下 EXE。")
        if not os.path.isfile(self.loader):
            raise EdlError("firehose programmer 不存在：" + self.loader)

        timeout = timeout or self.timeout
        argv = self._argv(cmd, extra)
        sink = _Sink(self.on_line, self.on_progress)
        box = {}

        def work():
            old_out, old_err = sys.stdout, sys.stderr
            # 回调里的 print 要落到进会话之前的那个流（CLI 是日志文件）；
            # GUI 模式下它是 None，用 devnull 兜住，反正不能指回 ROUTER。
            sink.real_out = old_out if old_out is not None else _DEVNULL
            ROUTER.target = sink
            sys.stdout = ROUTER
            sys.stderr = ROUTER
            try:
                args = _docopt(_edlmain.__doc__, version="3", argv=argv[1:])
                # 设备在 configure 阶段报的 MaxPayloadSizeToTargetInBytes 只有
                # 16384，而 edl 默认按 1MB 发包（--maxpayload 默认 0x100000）:
                #     WARN: NAK: MaxPayloadSizeToTargetInBytes sent by host
                #           1048576 larger than supported 16384
                # 每个包都被打回重试，96MB 的 boot 分区读到 100655104 字节后
                # 300 秒超时（实测）。按设备能力对齐，读写才跑得完。
                args["--maxpayload"] = "0x4000"
                # 第二个参数是 imported：edlmain 里写的是
                #     if imported == '': self.imported = True
                # 而 parse_cmd() 里 `if self.imported: return ""` —— 传空串会让
                # 命令名直接变成空字符串，run() 连上设备后在
                # `if self.imported: return self.exit()` 处立刻退出，
                # 一条命令都不执行。必须传非空的哨兵值。
                base = _edlmain.main(args, "__leaf5dump__")
                base.run()
                box["rc"] = 0
            except SystemExit as e:
                # edl 内部某些分支还是会 sys.exit，这里当正常结束处理
                box["rc"] = e.code if isinstance(e.code, int) else 0
            except Exception as e:
                box["err"] = "%s: %s" % (type(e).__name__, e)
            finally:
                try:
                    sink.flush()
                except Exception:
                    pass
                ROUTER.target = None
                sys.stdout = old_out
                sys.stderr = old_err
                box["done"] = True

        th = threading.Thread(target=work, daemon=True)
        t0 = time.time()
        th.start()
        th.join(timeout)
        self.last_output = ""       # sink 是行级回调，原文不在这儿留；排障看 GUI 日志
        if th.is_alive():
            self._poisoned = True
            raise EdlError("edl 超时（%d 秒）。设备可能不在 9008，或驱动没绑 WinUSB。\n"
                           "  超时后 USB 句柄状态不确定，已锁定本次会话 —— 重启工具再试。"
                           % timeout)
        if "err" in box:
            raise EdlError(box["err"])
        return box.get("rc", 0), time.time() - t0

    # -- 对外命令 ------------------------------------------------------
    def printgpt(self, timeout=120):
        """
        读分区表。这一步同时给出两件事：分区清单，以及哪个槽是 active。
        「该读 boot_a 还是 boot_b」就不用猜了。
        """
        rc, _ = self._call(["printgpt"], timeout=timeout)
        return rc

    def read(self, part, out_path, timeout=600):
        """r <分区> <文件>。只读命令，不写设备。"""
        out_path = os.path.abspath(out_path).replace("\\", "/")
        d = os.path.dirname(out_path)
        if d and not os.path.isdir(d):
            os.makedirs(d, exist_ok=True)
        rc, _ = self._call(["r", part, out_path], timeout=timeout)
        if not os.path.isfile(out_path):
            raise EdlError("edl 报成功但没生成文件：" + out_path)
        return out_path

    def reset(self, timeout=60):
        """
        退出下载模式让设备正常启动。

        这一步必须执行，哪怕前面全失败：设备停在 9008 时屏幕全黑，看起来像变砖。
        失败时抛异常，由调用方决定是否忽略。
        """
        return self._call(["reset"], timeout=timeout)

    def close(self):
        """尽力收尾。不抛异常。"""
        try:
            self.reset()
        except Exception:
            pass


# ----------------------------------------------------------------------
# Session：一次 9008 连接里做完 printgpt / r / reset
# ----------------------------------------------------------------------
class Session:
    """
    为什么要有这个类 —— 一句话：**edl 的命令行模式跑完一条命令不关 USB 句柄。**

    `edlmain.run()` 里只有在 `self.imported`（即 `main(args, "")`）为真、
    以及出错分支才会调 `self.exit()`：
        if self.fh.connect(sahara):
            if self.imported:
                return self.exit(cdc_close=False)     # imported 模式：不关
            elif not self.fh.handle_firehose(cmd, options):
                return self.exit(1)                   # 只有失败才关
    正常跑完 handle_firehose 成功后**直接 return，不调 exit，也就没有
    cdc.close()**。于是设备句柄留在进程里，下一次 connect() 走到
    get_active_configuration() 就报 errno 13：

        DeviceClass - [LIB]: Permission denied accessing 05c6:9008.

    实测就是：printgpt 那次成功，紧接着的 r 那次失败。

    Session 的做法是 `main(args, "")` 建立连接（imported 模式连上就返回、
    不执行命令、也不关设备），然后在同一个 cdc 上连续调 handle_firehose。
    一条连接干完全部活，没有"第二次打开"这回事。
    """

    def __init__(self, loader=None):
        _prepare()
        self.loader = loader or loader_path()
        self.base = None
        self.fh = None
        self.options = None
        self.logged = False

    # -- 内部 ----------------------------------------------------------
    class _Route:
        def __init__(self, on_line, on_progress):
            self.sink = _Sink(on_line, on_progress)

        def __enter__(self):
            self.old = (sys.stdout, sys.stderr)
            self.sink.real_out = (sys.stdout if sys.stdout is not None else _DEVNULL)
            ROUTER.target = self.sink
            sys.stdout = ROUTER
            sys.stderr = ROUTER
            return self.sink

        def __exit__(self, *exc):
            try:
                self.sink.flush()
            except Exception:
                pass
            ROUTER.target = None
            sys.stdout, sys.stderr = self.old
            return False

    def _run(self, fn, timeout, what):
        """USB 操作放子线程，主线程带超时等 —— run() 里的等待循环是死循环。"""
        box = {}

        def work():
            try:
                box["v"] = fn()
            except SystemExit as e:
                box["rc"] = e.code if isinstance(e.code, int) else 0
            except Exception as e:
                box["err"] = "%s: %s" % (type(e).__name__, e)
            finally:
                box["done"] = True

        th = threading.Thread(target=work, daemon=True)
        t0 = time.time()
        th.start()
        th.join(timeout)
        if th.is_alive():
            raise EdlError("%s超时（%d 秒）。设备可能已经掉了，重启工具再试。"
                           % (what, timeout))
        if "err" in box:
            raise EdlError(box["err"])
        return box.get("v"), box.get("rc", 0), time.time() - t0

    # -- 对外 ----------------------------------------------------------
    def open(self, on_line=None, on_progress=None, timeout=90):
        """连上 firehose。imported 模式：连上即停，不执行命令，也不关设备。"""
        if not self.loader or not os.path.isfile(self.loader):
            raise EdlError("找不到 firehose programmer：%r" % (self.loader,))

        argv = ["edlmain.py", "--loader=" + self.loader.replace("\\", "/"),
                "--memory=eMMC", "printgpt"]

        def fn():
            with Session._Route(on_line, on_progress):
                args = _docopt(_edlmain.__doc__, version="3", argv=argv[1:])
                base = _edlmain.main(args, "")   # "" = imported：连上就 return
                rc = base.run()
                self.base = base
                return rc

        rc, code, _ = self._run(fn, timeout, "连接 9008 ")
        if rc is None:
            # run() 抛 SystemExit 时返回值在 code 里（edl 有些分支直接 sys.exit）
            rc = code

        if self.base is None or getattr(self.base, "fh", None) is None:
            raise EdlError("没建立起 firehose 会话。设备可能不在 9008，"
                           "或者 WinUSB 驱动没绑上。")
        if rc:
            raise EdlError("firehose 握手失败（rc=%s）。设备可能不在下载模式，"
                           "或者 programmer 不对。" % rc)
        self.fh = self.base.fh
        self.options = self.base.parse_option(self.base.args)
        # reset 分支要求 --resetmode 非空，先填上，后面 reset() 直接用
        self.options["--resetmode"] = "reset"
        return True

    def printgpt(self, on_line=None, on_progress=None, timeout=120):
        if not self.fh:
            raise EdlError("会话没建立，先调 open()")

        def fn():
            with Session._Route(on_line, on_progress):
                return self.fh.handle_firehose("printgpt", self.options)

        return self._run(fn, timeout, "读分区表")[0]

    def read(self, part, out_path, on_line=None, on_progress=None, timeout=900,
             place=None, expect=None, chunk=4 * 1024 * 1024, attempts=6):
        """
        读一个分区到 out_path。

        place=(lun, start_sector, sectors) —— 该分区在 GPT 里的位置。
        expect=字节数 —— 期望长度（一般就是 sectors*512）。

        为什么给了 place 就自己分块读、不走 edl 的 `r`：

        edl 的 cmd_read 是一条 read 命令读到底（boot_b 一次 96MB），中途
        USB IN 端点一旦 stall（DeviceClass - USBError(32, 'Pipe error')），
        设备就不再发数据，host 只能收工 —— 实测读到 100641375 字节就停，
        还差 21921。重连一次要重新进 9008、重新握手，代价太大。

        分块读把 96MB 切成 4MB 一段，每段一条独立 read 命令：
          · 单段 stall 只损失这一段的剩余部分，从断点整扇区续读
          · 每段结束设备都会回 ACK，XML 流重新同步，不会一直错位
          · 块内重试 6 次，块与块之间天然有喘息
        代价是多发 23 条命令，实测总耗时反而更短（没有长时间 stall）。
        """
        if not self.fh:
            raise EdlError("会话没建立，先调 open()")
        out_path = os.path.abspath(out_path)
        d = os.path.dirname(out_path)
        if d and not os.path.isdir(d):
            os.makedirs(d, exist_ok=True)
        ss = int(self.fh.firehose.cfg.SECTOR_SIZE_IN_BYTES) or 512
        # edl 内部用 open(filename, "wb")，Windows 上正斜杠没问题，但保持原生更稳
        self.options["<partitionname>"] = part
        self.options["<filename>"] = out_path

        if not (place and expect):
            def fn():
                with Session._Route(on_line, on_progress):
                    return self.fh.handle_firehose("r", self.options)

            self._run(fn, timeout, "读取分区 ")
            if not os.path.isfile(out_path):
                raise EdlError("edl 报成功但没生成文件：%s" % out_path)
            return out_path

        lun, start, sectors = place
        per = max(1, int(chunk) // ss)          # 每块多少扇区
        per_timeout = max(60, int(timeout) // max(1, (sectors + per - 1) // per))
        # 从零开始：不走 handle_firehose，前面没写过这个文件，直接建空文件
        with open(out_path, "wb"):
            pass

        pos = 0
        t0 = time.time()
        blk = 0
        while pos < sectors:
            n = min(per, sectors - pos)
            blk += 1
            block_off = pos * ss
            need = n * ss
            ok = False
            last = ""
            for tries in range(1, attempts + 1):
                # 每轮先把文件截回块起点：上一轮如果读错位/读多了，脏数据
                # 会顺着 append 一直带到后面，截掉最省事也最可靠。
                try:
                    if os.path.getsize(out_path) > block_off:
                        os.truncate(out_path, block_off)
                except OSError:
                    pass
                if tries > 1:
                    self._drain()

                def one(b=start + pos, c=n):
                    with Session._Route(on_line, on_progress):
                        return self.fh.firehose.cmd_read(
                            lun, b, c, out_path, display=False, append=True)

                try:
                    self._run(one, per_timeout, "读 %s 第 %d 块 " % (part, blk))
                except EdlError as e:
                    last = str(e)
                    time.sleep(0.2)
                    continue

                got = os.path.getsize(out_path) - block_off
                if got == need:
                    ok = True
                    break
                # 长度必须**正好**等于本块应有大小。多了少了都说明这条 read
                # 命令的数据流不可信（EPIPE 之后最容易出现"长度凑够但内容错位"）。
                last = "只拿到 %d/%d 字节" % (got, need)
                if on_line:
                    on_line("  [!] %s 第 %d 块重来（%s）" % (part, blk, last))
                time.sleep(0.2)
            if not ok:
                raise EdlError("%s 第 %d 块连续 %d 次读不满：%s"
                               % (part, blk, attempts, last))
            pos += n
            if on_line:
                on_line("  %s %d/%d 字节  %.1fs" % (
                    part, min(expect, pos * ss), expect, time.time() - t0))
        return out_path

    def _drain(self, rounds=256):
        """
        把 IN 端点里残留的字节读空。

        短读 / EPIPE 之后设备可能还在发上一次 read 的尾巴。不清空的话，下一条
        read 命令读到的头几个包是上一块的残留 —— 数据整体错位，但文件长度照样
        能凑够，sha256 却对不上。这种错误在长度检查里看不出来，必须源头清干净。
        """
        try:
            cdc = self.fh.firehose.cdc
            ep = cdc.EP_IN
            buf = cdc.buffer
        except Exception:
            return
        for _ in range(rounds):
            try:
                n = ep.read(buf, 60)
            except Exception:
                break
            if not n:
                break

    def reset(self, on_line=None, timeout=60):
        """让设备离开 9008。失败不抛，交给调用方决定。"""
        if not self.fh:
            return False

        def fn():
            with Session._Route(on_line, None):
                return self.fh.firehose.cmd_reset("reset")

        try:
            return self._run(fn, timeout, "reset ")[0]
        except Exception:
            return False

    def close(self):
        """关掉 USB 句柄。忘了这一步 = 下一次连接 errno 13。"""
        b, self.base, self.fh = self.base, None, None
        if b is None:
            return
        try:
            b.exit(0, cdc_close=True)
        except Exception:
            try:
                b.cdc.close()
            except Exception:
                pass


# ----------------------------------------------------------------------
# 纯探测：不加载 edl，只用 pyusb 看 9008 在不在
# ----------------------------------------------------------------------
QC_VID = 0x05C6
EDL_PIDS = {
    0x9008: "9008 EDL",
    0x900E: "900E EDL(memdump)",
    0x901D: "901D diag",
    0x9025: "9025 EDL",
}


def find_9008():
    """
    返回 [(pid, label, serial)]。空列表 = 没有 9008 设备。

    用 pyusb 直接枚举，不需要 adb，也不需要等 edl 加载。
    """
    _prepare()
    out = []
    try:
        import usb.core
    except Exception:
        return out
    try:
        for d in usb.core.find(find_all=True, idVendor=QC_VID):
            pid = d.idProduct
            if pid not in EDL_PIDS:
                continue
            try:
                sn = d.serial_number or ""
            except Exception:
                sn = ""
            out.append((pid, EDL_PIDS[pid], sn))
    except Exception:
        pass
    return out


def wait_9008(limit=25.0, step=0.4, should_stop=None):
    """等 9008 出现。返回 (ok, 等待秒数)。"""
    t0 = time.time()
    while time.time() - t0 < limit:
        if should_stop and should_stop():
            break
        if find_9008():
            return True, time.time() - t0
        time.sleep(step)
    return False, time.time() - t0


def env_report():
    """一行环境自检，日志窗口开头会打。"""
    parts = []
    ls = loader_candidates()
    if ls:
        parts.append("loader %s (%d KB)" % (os.path.basename(ls[0]),
                                            os.path.getsize(ls[0]) // 1024))
    else:
        parts.append("loader 缺失")
    try:
        import libusb_package
        p = libusb_package.find_library("libusb-1.0")
        parts.append("libusb %s" % (os.path.basename(p) if p else "?"))
    except Exception:
        parts.append("libusb 缺失")
    dev = find_9008()
    parts.append("9008 " + ("在线 " + dev[0][1] if dev else "未发现"))
    return " | ".join(parts)
