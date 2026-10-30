# -*- coding: utf-8 -*-
"""
elfsyms.py — 纯标准库的 ELF64 符号表解析（AArch64 / ARM32）。

为什么不用 nm/readelf：
  EXE 是自包含的，目标机（用户的 Windows）不一定装 binutils。
  这里只需要"名字 → 地址"和"section 布局"，用 struct 手工解就够了。

支持的输入：
  - 带 .symtab 的 vmlinux（厂商固件里通常是带符号的）
  - 只有 .dynsym 的 stripped ELF（能拿到导出符号，够用一部分锚点）
  - 裸二进制（无 ELF 头）会抛 ElfError，调用方应改用 PanicProbe 或其他方式

作者注：4.19 内核的 vmlinux.elf 是 ET_EXEC、非 PIE 时代产物，
_link 基址固定 0xffffff8008080000 一类，所以所有 OFF 都要减 _text。
"""

import os
import re
import struct

ELF_MAGIC = b"\x7fELF"

SHT_SYMTAB = 2
SHT_DYNSYM = 11
STT_OBJECT = 1
STT_FUNC = 2


class ElfError(Exception):
    pass


# ----------------------------------------------------------------------
# kallsyms 文本（设备上 /proc/kallsyms 的导出，格式 `地址 类型 名字`）
# ----------------------------------------------------------------------
# 为什么这条路能替代 vmlinux.elf：
#   target.h 里每个宏都是「符号地址 − _text」，是个**差值**。
#   差值跟 KASLR 无关（两边一起平移），跟内核有没有 strip 也无关，
#   跟文件在不在设备上也无关 —— 只要 /proc/kallsyms 里的地址没有被
#   kptr_restrict 打成 0，这份文本就够了。
#   设备上 `su -c "cat /proc/kallsyms"` 一条命令就能拿，比翻固件包快。

_KALLSYMS_LINE = re.compile(r"^([0-9a-fA-F]{8,16})\s+(\S)\s+(\S+)\s*$")


def looks_like_kallsyms(path, probe=1 << 20):
    """判断一份文件是不是 kallsyms 文本（不是 ELF、也不是二进制）。"""
    try:
        if os.path.getsize(path) < 32:
            return False
        with open(path, "rb") as f:
            head = f.read(probe)
    except OSError:
        return False
    if head[:4] == ELF_MAGIC:
        return False
    # 二进制文件里通常有大量 NUL，kallsyms 文本不会
    if head.count(b"\x00") > 8:
        return False
    txt = head.decode("utf-8", "replace")
    lines = [l.strip() for l in txt.splitlines() if l.strip()][:200]
    if len(lines) < 4:
        return False
    ok = sum(1 for l in lines if _KALLSYMS_LINE.match(l))
    if ok >= len(lines) * 0.8:
        return True
    # 系统符号表（System.map）是「地址 类型 名字」，kallsyms 是「地址 类型 名字」
    # 两者格式相同；上一步已覆盖。剩下一类是全 0 地址的退化 kallsyms，
    # 单看格式同样能过 —— 这里不再单独放行，由调用方统计 zeroed 后再报错。
    return False


class Kallsyms(object):
    """
    把 kallsyms 文本伪装成 Elf64 用（只实现 symbols() / close() / with）。

    zeroed 记录地址为 0 的条数：kptr_restrict=1 时普通用户读到的是全 0，
    =2 时连 root 也读不到。全 0 的文本在这里会把符号全丢掉，
    调用方必须检查这个数而不是当成"符号不存在"。
    """

    def __init__(self, path):
        self.path = path
        self.size = os.path.getsize(path)
        self.total = 0
        self.zeroed = 0
        self.skipped = 0
        syms = {}
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                m = _KALLSYMS_LINE.match(line)
                if not m:
                    parts = line.split()
                    if len(parts) < 3 or not re.match(
                            r"^[0-9a-fA-F]{8,16}$", parts[0]):
                        self.skipped += 1
                        continue
                    addr, typ, name = parts[0], parts[1], parts[2]
                else:
                    addr, typ, name = m.group(1), m.group(2), m.group(3)
                self.total += 1
                try:
                    v = int(addr, 16)
                except ValueError:
                    self.skipped += 1
                    continue
                if v == 0:
                    self.zeroed += 1
                    continue
                # 同名取第一次出现（与 Elf64.symbols() 的取舍一致）
                if name not in syms:
                    syms[name] = (v, 0, ord(typ[0]) if typ else 0, 0)
        self._syms = syms

    def symbols(self):
        return self._syms

    def close(self):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *a):
        pass


def open_syms(path):
    """
    统一符号来源入口：ELF 走 Elf64，文本走 Kallsyms，裸 ARM64 Image 走 ImageSyms。
    调用方拿到的东西只有 symbols() 可用，三者接口一致。
    """
    if looks_like_kallsyms(path):
        return Kallsyms(path)
    if looks_like_image(path):
        return ImageSyms(path)
    return Elf64(path)


IMAGE_MAGIC_POS = 0x38
IMAGE_MAGIC = b"ARM\x64"


def looks_like_image(path):
    """
    裸 ARM64 Image：0x38 处是 ARM\\x64。这是 U-Boot/ABL 认可的 Image 头，
    boot 分区里去掉 header 之后的 kernel 段就是它。
    """
    try:
        if os.path.getsize(path) < (1 << 20):
            return False
        with open(path, "rb") as f:
            head = f.read(0x10000)
    except OSError:
        return False
    if head[:4] == ELF_MAGIC:
        return False
    if head[:8] == b"ANDROID!":
        return False
    return head[IMAGE_MAGIC_POS:IMAGE_MAGIC_POS + 4] == IMAGE_MAGIC


class ImageSyms(object):
    """
    把裸内核镜像的 kallsyms 反解结果包成和 Elf64 一样的接口。

    Elf64.symbols() 返回 {名字: (地址, size, type, shndx)}。这里把「相对 _text
    的偏移」当作地址填进去，并让 _text 自己等于 0 —— 于是 extract_offsets 里的
    `syms[sym][0] - base` 算出来正好是偏移，不需要改下游任何一行。
    """

    def __init__(self, path):
        import imageksym
        self.path = path
        self._ks = imageksym.ImageKallsyms(path)
        self._syms = None

    def symbols(self):
        if self._syms is None:
            d = self._ks.symbols()
            self._syms = {k: (v, 0, 0, 0) for k, v in d.items()}
        return self._syms

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self._ks.close()


class Elf64(object):
    """最小可用的 ELF64 读取器。只解析到"能取符号"为止。"""

    def __init__(self, path):
        self.path = path
        self.size = os.path.getsize(path)
        self.f = open(path, "rb")
        hdr = self.f.read(64)
        if len(hdr) < 64 or hdr[:4] != ELF_MAGIC:
            self.f.close()
            raise ElfError("不是 ELF 文件（找不到 \\x7fELF 魔数）")

        ei_class = hdr[4]        # 1=32bit 2=64bit
        ei_data = hdr[5]         # 1=LE 2=BE
        if ei_data != 1:
            self.f.close()
            raise ElfError("只支持小端 ELF（大端内核不在此工具的适用范围内）")
        if ei_class != 2:
            self.f.close()
            raise ElfError("这是 32 位 ELF。Leaf5 的 vmlinux 是 AArch64，"
                           "拿错文件了？")

        # e_type(0x10,2) e_machine(0x12,2)
        self.e_type, self.e_machine = struct.unpack("<HH", hdr[0x10:0x14])
        self.e_shoff, = struct.unpack("<Q", hdr[0x28:0x30])
        self.e_shentsize, self.e_shnum, self.e_shstrndx = struct.unpack(
            "<HHH", hdr[0x3A:0x40])
        # e_phoff(0x20) e_phentsize(0x36) e_phnum(0x38)
        self.e_phoff, = struct.unpack("<Q", hdr[0x20:0x28])
        self.e_phentsize, self.e_phnum = struct.unpack("<HH", hdr[0x36:0x3A])

        if self.e_shoff == 0 or self.e_shnum == 0:
            self.f.close()
            raise ElfError("ELF 没有 section header 表（被 objcopy --strip-section-headers "
                           "处理过？），取不到符号")

        self.sections = self._read_sections()
        self._symcache = None

    # ------------------------------------------------------------------
    def _read_sections(self):
        """读 section header 表，返回 [{name,type,addr,offset,size,link,entsize}]"""
        self.f.seek(self.e_shoff)
        raw = self.f.read(self.e_shentsize * self.e_shnum)
        if len(raw) < self.e_shentsize * self.e_shnum:
            raise ElfError("section header 表被截断，文件不完整")

        secs = []
        for i in range(self.e_shnum):
            b = raw[i * self.e_shentsize:(i + 1) * self.e_shentsize]
            s = {}
            s["name_off"], = struct.unpack("<I", b[0:4])
            s["type"], = struct.unpack("<I", b[4:8])
            s["flags"], = struct.unpack("<Q", b[8:16])
            s["addr"], = struct.unpack("<Q", b[0x10:0x18])
            s["offset"], = struct.unpack("<Q", b[0x18:0x20])
            s["size"], = struct.unpack("<Q", b[0x20:0x28])
            s["link"], = struct.unpack("<I", b[0x28:0x2C])
            s["info"], = struct.unpack("<I", b[0x2C:0x30])
            s["addralign"], = struct.unpack("<Q", b[0x30:0x38])
            s["entsize"], = struct.unpack("<Q", b[0x38:0x40])
            secs.append(s)

        # section 名表
        shstr = b""
        if self.e_shstrndx < len(secs):
            st = secs[self.e_shstrndx]
            self.f.seek(st["offset"])
            shstr = self.f.read(st["size"])

        for s in secs:
            s["name"] = self._cstr(shstr, s["name_off"])
        return secs

    @staticmethod
    def _cstr(buf, off):
        if off >= len(buf):
            return ""
        end = buf.find(b"\x00", off)
        if end < 0:
            end = len(buf)
        return buf[off:end].decode("utf-8", "replace")

    def find_section(self, name):
        for s in self.sections:
            if s["name"] == name:
                return s
        return None

    # ------------------------------------------------------------------
    def symbols(self):
        """返回 {name: (value, size, info, shndx)}，.symtab 优先，缺失时退 .dynsym"""
        if self._symcache is not None:
            return self._symcache

        out = {}
        for want in (SHT_SYMTAB, SHT_DYNSYM):
            tabs = [s for s in self.sections if s["type"] == want]
            if not tabs:
                continue
            for tab in tabs:
                if tab["link"] >= len(self.sections):
                    continue
                strtab = self.sections[tab["link"]]
                self.f.seek(strtab["offset"])
                strs = self.f.read(strtab["size"])
                ent = tab["entsize"] or 24
                self.f.seek(tab["offset"])
                blob = self.f.read(tab["size"])
                n = len(blob) // ent
                for i in range(n):
                    b = blob[i * ent:(i + 1) * ent]
                    if len(b) < 24:
                        break
                    st_name, = struct.unpack("<I", b[0:4])
                    st_info = b[4]
                    st_shndx, = struct.unpack("<H", b[6:8])
                    st_value, = struct.unpack("<Q", b[8:16])
                    st_size, = struct.unpack("<Q", b[0x10:0x18])
                    if st_name == 0 or st_value == 0:
                        continue
                    nm = self._cstr(strs, st_name)
                    if not nm:
                        continue
                    # 同名以第一次出现为准（symtab 在 dynsym 之前，本地符号优先）
                    if nm not in out:
                        out[nm] = (st_value, st_size, st_info, st_shndx)
            if out:                       # 拿到了就不再看 dynsym
                break

        self._symcache = out
        return out

    def close(self):
        try:
            self.f.close()
        except Exception:
            pass

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()


# ----------------------------------------------------------------------
# target.h 里的宏 → vmlinux 符号名
# ----------------------------------------------------------------------
# 下面这张表只是"模板读不到时的兜底"。正常路径是 discover_macros()：
# 从 target.h 里扫出全部 `#define XXX_OFF 0x...ULL`，去掉 _OFF 转小写当符号名去查。
# 这么做是因为硬编码表必然会漏 —— 实测模板里有 62 个 _OFF 宏，手写表只能覆盖 20 个。
#
# 表里绝对不该进来的（不是内核符号）：TASK_CRED_OFF / WAITER_LOCAL_OFF /
# PRCTL_WAITER_WORD_DEFAULT / PRCTL_FRAME_TOTAL —— 属于结构体布局与栈几何，
# 符号表里没有对应物，必须人工反汇编或 panic 定标。
SYM_MAP = [
    ("INIT_TASK_OFF",             "init_task"),
    ("INIT_CRED_OFF",             "init_cred"),
    ("INIT_NSPROXY_OFF",          "init_nsproxy"),
    ("INIT_UTS_NS_OFF",           "init_uts_ns"),
    ("INIT_PID_NS_OFF",           "init_pid_ns"),
    ("MODPROBE_PATH_OFF",         "modprobe_path"),
    ("CORE_PATTERN_OFF",          "core_pattern"),
    ("SELINUX_STATE_OFF",         "selinux_state"),
    ("SELINUX_ENFORCING_OFF",     "selinux_enforcing"),
    ("KMALLOC_CACHES_OFF",        "kmalloc_caches"),
    ("KMEM_CACHE_CREATE_OFF",     "kmem_cache_create_usercopy"),
    ("COMMIT_CREDS_OFF",          "commit_creds"),
    ("PREPARE_KERNEL_CRED_OFF",   "prepare_kernel_cred"),
    ("DO_FUTEX_OFF",              "do_futex"),
    ("REMOVE_WAITER_OFF",         "remove_waiter"),
    ("RT_MUTEX_ADJUST_OFF",       "rt_mutex_adjust_prio_chain"),
    ("ASHMEM_FOPS_OFF",           "ashmem_fops"),
    ("PIPE_FOPS_OFF",             "pipefifo_fops"),
    ("ANON_PIPE_BUF_OPS_OFF",     "anon_pipe_buf_ops"),
    ("KMALLOC_CGROUP_OFF",        "kmalloc_caches"),   # 别名，按需删
]

# 表里不是每个内核都有，缺一个不该整体失败。这些是可选的。
OPTIONAL_SYMS = {
    "INIT_PID_NS_OFF", "KMALLOC_CGROUP_OFF", "SELINUX_ENFORCING_OFF",
    "ASHMEM_FOPS_OFF",
}

# 这些宏长得像偏移但不是内核符号，自动发现时必须跳过
SKIP_MACROS = {
    "KIMAGE_TEXT_BASE", "P0_PAGE_OFFSET", "P0_PHYS_OFFSET",
    "KERNELSNITCH_IDENTITY_START", "KERNELSNITCH_IDENTITY_END",
    "DIRECT_MAP_BASE", "DIRECT_MAP_END", "VMEMMAP_START",
    "UTS_ORACLE_MARKER_LE",
}

_OFF_RE = re.compile(
    r"^#define\s+([A-Z][A-Z0-9_]*_OFF)\s+0[xX][0-9a-fA-F]+ULL", re.M)


def discover_macros(template_path):
    """
    从 target.h 里扫出所有 `#define XXX_OFF 0x...ULL`，
    把 XXX 转小写当内核符号名去查。返回 [(MACRO, symname)]。

    为什么这么做：模板里 62 个 _OFF 宏，硬编码表覆盖不全，
    而且厂商换固件时可能新增宏，自动发现能跟上。
    """
    with open(template_path, encoding="utf-8", errors="replace") as f:
        txt = f.read()
    out = []
    seen = set()
    for m in _OFF_RE.finditer(txt):
        macro = m.group(1)
        if macro in SKIP_MACROS or macro in seen:
            continue
        seen.add(macro)
        out.append((macro, macro[:-4].lower()))
    return out


def offset_of(elf, symname):
    """返回 symname 相对 _text 的偏移；符号不存在返回 None"""
    syms = elf.symbols()
    if "_text" not in syms:
        raise ElfError("vmlinux 里没有 _text 符号，无法建立偏移基准")
    base = syms["_text"][0]
    if symname not in syms:
        return None
    return syms[symname][0] - base


def extract_offsets(elf_path, template_path=None, log=None):
    """
    返回 (offsets, missing)。
      offsets: {MACRO: int}
      missing: [(MACRO, symname)] —— 模板里有、内核里查不到的

    template_path 给出时自动发现宏；不给就用兜底的 SYM_MAP。
    """
    def say(s):
        if log:
            log(s)

    pairs = discover_macros(template_path) if template_path else SYM_MAP
    if template_path:
        say(f"  从模板发现 {len(pairs)} 个 *_OFF 宏")

    got = {}
    missing = []
    with open_syms(elf_path) as e:
        syms = e.symbols()
        if not syms:
            raise ElfError(
                "这份符号来源里一个有效地址都没有。\n"
                "  如果是 kallsyms 文本：kptr_restrict 把地址打成 0 了，\n"
                "  先在设备上执行 `su -c 'echo 0 > /proc/sys/kernel/kptr_restrict'`\n"
                "  （或 `su -c 'cat /proc/kallsyms'` 时确认输出地址不是 0000000000000000）")
        if "_text" not in syms:
            raise ElfError(
                "里没有 _text 符号，无法建立偏移基准。\n"
                "  vmlinux.elf 被 strip 过，或者这是只含模块符号的 kallsyms 片段。\n"
                "  需要完整符号表（带 _text 的那份）")
        base = syms["_text"][0]
        kind = ("kallsyms 文本" if isinstance(e, Kallsyms)
                else "内核 Image" if isinstance(e, ImageSyms) else "ELF")
        say(f"  来源 {kind}   _text = 0x{base:016X}   符号总数 {len(syms)}")
        if isinstance(e, Kallsyms):
            if e.zeroed:
                raise ElfError(
                    f"kallsyms 里有 {e.zeroed}/{e.total} 条地址是 0，"
                    f"偏移全部不可用。\n"
                    f"  设备上先关掉地址隐藏：\n"
                    f"    su -c 'echo 0 > /proc/sys/kernel/kptr_restrict'\n"
                    f"    su -c 'cat /proc/kallsyms' | head\n"
                    f"  确认第一列不是全 0 再重新导出。")
            say(f"  解析 {e.total} 行，跳过 {e.skipped} 行非符号格式")

        for macro, sym in pairs:
            if sym not in syms:
                # 有些 _OFF 宏指向的是硬编码常量（bss 里手工挑的槽位），
                # 内核里本来就没这个符号，不算错误
                missing.append((macro, sym))
                say(f"  [无符号] {macro:<30} {sym}")
                continue
            off = syms[sym][0] - base
            got[macro] = off
            say(f"  {macro:<30} 0x{off:012X}   ({sym})")

    return got, missing

