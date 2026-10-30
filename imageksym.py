"""
imageksym.py — 从裸 ARM64 内核镜像里反解 kallsyms 表

设备没 root、网上又拿不到任何 vmlinux 时，唯一还能用的原始材料就是
boot 分区的 kernel 段本身。kallsyms 的原始数据（token 压缩的符号名表 +
相对 _text 的偏移数组）是编译进 .rodata 的，跟 /proc/kallsyms 同源 ——
/proc 只是内核启动后把这些表展开成文本。

布局（4.19 / 5.x ARM64，按 vmlinux.lds 的 KALLSYMS 段顺序）：

    kallsyms_num_syms    .long   × 1
    kallsyms_offsets     .long   × N      符号地址 - _text（本机型实测就是纯偏移）
    （对齐 padding）
    kallsyms_names       len + token 索引  × N
    kallsyms_markers     .quad   × ceil(N/256)   每 256 个符号在 names 内的字节偏移
    （对齐 padding）
    kallsyms_token_table 256 个 \\0 结尾的短串
    kallsyms_token_index .short  × 256    每个 token 在 table 内的偏移

没有符号名可以做锚点，所以按「结构自证」一步一步倒推：先用
token_index 的严格递增特征定住尾部，再用 markers 的单调递增定住 names
末尾，最后用 markers 的字节偏移交叉验证出 names 起点。每一步都有独立的
校验条件，任何一步不成立就整体放弃，不会吐出一份看起来像但错位的表。

只依赖标准库。60MB 镜像全流程约 3~6 秒（一次性操作，向导里有进度）。
"""

import bisect
import mmap
import os
import re
import struct

MAX_IMAGE = 1 << 30          # 超过 1GB 的一定不是内核 Image
TAIL_RATIO = 0.62            # kallsyms 表一定在 .rodata 尾部，从后 38% 开始找
MAX_TABLE = 16384            # token_table 合理的上限
MAX_OFFSET = 0x8000000       # 符号偏移上限 128MB（镜像本体不会更大）


class KsymError(Exception):
    pass


def _u16(buf, off, n):
    return struct.unpack_from("<%dH" % n, buf, off)


def _u32(buf, off, n):
    return struct.unpack_from("<%dI" % n, buf, off)


def _u64(buf, off, n):
    return struct.unpack_from("<%dQ" % n, buf, off)


class ImageKallsyms(object):
    """
    裸 ARM64 Image 的 kallsyms 反解器。

        ks = ImageKallsyms("kernel")
        syms = ks.symbols()        # {"_text": 0, "start_kernel": 0x2f1c40, ...}
        info = ks.info()           # 各结构的偏移，排障用

    symbols() 的值是「符号地址 - _text」，直接就是 target.h 里要填的数。
    """

    def __init__(self, path):
        self.path = path
        size = os.path.getsize(path)
        if size < (1 << 20):
            raise KsymError("文件只有 %d 字节，不可能是内核镜像" % size)
        if size > MAX_IMAGE:
            raise KsymError("文件 %d 字节，超过 1GB，不是内核 Image" % size)
        self._f = open(path, "rb")
        self._m = mmap.mmap(self._f.fileno(), 0, access=mmap.ACCESS_READ)
        self.buf = self._m
        self.size = size
        self._toks = None
        self._names = None
        self._offsets = None
        self._layout = {}

    # -- 生命周期 ---------------------------------------------------------
    def close(self):
        try:
            self._m.close()
        finally:
            self._f.close()

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()

    # -- 0. 确认这是 ARM64 Image 而不是随便一个二进制 --------------------
    def check_arm64(self):
        """
        ARM64 Image 头：0x38 处必须是 'ARM\\x64'（小端 magic 0x644d5241）。
        boot.img 的 'ANDROID!' 头在这里会被认出来并给出更准确的说法。
        """
        head = self.buf[:8]
        if head == b"ANDROID!":
            raise KsymError("这是 boot.img（有 ANDROID! 头），不是内核 Image。"
                            "先用工具里的「解出 vmlinux」把 kernel 段切出来")
        if self.size >= 0x40 and self.buf[0x38:0x3C] == b"ARM\x64":
            return True
        # 有些厂商镜像前面被贴了别的头，允许带偏移再找一次
        win = self.buf[:0x10000]
        i = win.find(b"ARM\x64")
        if i > 0 and (i - 0x38) >= 0:
            self._hdr_off = i - 0x38
            return True
        raise KsymError("0x38 处没有 ARM64 magic（ARM\\x64），不是裸内核 Image。"
                        "如果这是 ELF，用 vmlinux 那条路；如果是 boot.img，先解包")

    # -- 1. token_index：256 个严格递增的 u16，首项 0 --------------------
    def find_token_index(self, log=None):
        start = int(self.size * TAIL_RATIO) & ~3
        start = max(0, start - 4096)
        buf = self.buf
        n = self.size - 512
        cands = []
        # 粗筛：前四项是 0、小值、稍大、再稍大（实测 [0,3,6,10]）。
        # 用模式把候选压到几十个，否则 60MB 里 \x00\x00 有上百万个。
        pat = re.compile(rb"\x00\x00[\x01-\x0f]\x00[\x02-\x20]\x00", re.S)
        pos = start
        while pos < n:
            m = pat.search(buf, pos)
            if not m:
                break
            off = m.start()
            pos = off + 1
            if off & 1:
                continue
            try:
                idx = _u16(buf, off, 256)
            except struct.error:
                break
            if idx[0] != 0 or idx[255] >= MAX_TABLE:
                continue
            if idx[1] < 1 or idx[1] > 64:
                continue
            ok = True
            prev = idx[0]
            for v in idx[1:]:
                if v <= prev:
                    ok = False
                    break
                prev = v
            if ok:
                cands.append(off)
        if log:
            log("  token_index 候选 %d 个" % len(cands))
        return cands

    # -- 2. token_table：紧邻 token_index 之前，256 个 \0 结尾短串 --------
    def decode_table(self, idx_off, log=None):
        buf = self.buf
        idx = _u16(buf, idx_off, 256)
        # table 末尾到 idx_off 之间可能有对齐 padding（本机型实测 119 字节）
        for pad in range(0, 513):
            end = idx_off - pad
            if end <= 0:
                break
            # 最后一个 token 起点由 idx[255] 决定，长度未知，枚举 0..40
            for last in range(0, 41):
                t = end - idx[255] - last - 1
                if t < 0:
                    break
                if last and buf[t + idx[255] + last] != 0:
                    continue
                toks = []
                ok = True
                for i in range(256):
                    s = t + idx[i]
                    if s >= end:
                        ok = False
                        break
                    e = buf.find(b"\x00", s, end)
                    if e < 0:
                        ok = False
                        break
                    seg = buf[s:e]
                    if len(seg) > 40:
                        ok = False
                        break
                    for c in seg:
                        if not (32 <= c < 127):
                            ok = False
                            break
                    if not ok:
                        break
                    toks.append(seg)
                if not ok or len(toks) != 256:
                    continue
                # 相邻 token 必须首尾相接（这是最硬的一条校验）
                good = True
                for i in range(255):
                    s = t + idx[i]
                    e = buf.find(b"\x00", s, end)
                    if e + 1 != t + idx[i + 1]:
                        good = False
                        break
                if not good:
                    continue
                if log:
                    log("  token_table @ 0x%X  长 %d  末 token %r"
                        % (t, end - t, toks[255]))
                return t, toks
        return None, None

    # -- 3. markers：u64 单调递增，首项 0，紧邻 token_table 之前 ---------
    def find_markers(self, table_start, log=None):
        buf = self.buf
        # markers 与 table 之间实测有 24 字节 padding，往前扫 256 字节足够
        for pad in range(0, 257, 8):
            end = table_start - pad
            if end <= 0:
                break
            for k in range(60, 4000):          # markers 项数上限（N <= 102 万）
                st = end - k * 8
                if st < 0:
                    break
                if _u64(buf, st, 1)[0] != 0:   # 首项必须 0
                    continue
                last = _u64(buf, end - 8, 1)[0]
                if last < 1024 or last > (1 << 24):
                    continue
                # 抽查 8 个点是否单调
                step = max(1, (k - 1) // 8)
                prev = -1
                ok = True
                for i in range(0, k, step):
                    v = _u64(buf, st + i * 8, 1)[0]
                    if v <= prev:
                        ok = False
                        break
                    prev = v
                if not ok:
                    break                     # st 越往前越不可能，直接换 pad
                vals = _u64(buf, st, k)
                if all(vals[i] < vals[i + 1] for i in range(k - 1)):
                    if log:
                        log("  markers @ 0x%X  项数 %d  末项 %d" % (st, k, last))
                    return st, k
        return None, None

    # -- 4. names 起点：用 markers 的字节偏移交叉验证 --------------------
    def find_names(self, markers_off, k, log=None):
        buf = self.buf
        names_end = markers_off
        mk = _u64(buf, markers_off, k)
        # 第 (k-1)*256 个符号的起点 = names_start + mk[k-1]
        # 从它往后只剩 1..256 条，总长不会超过 8192 字节
        anchor = mk[k - 1]
        lo = names_end - 8192
        hi = names_end
        if lo < 0:
            raise KsymError("markers 末项 %d 太大，names 区超出文件" % anchor)
        hits = []
        for p in range(lo, hi + 1):
            s = p - anchor
            if s < 0:
                continue
            l = buf[p]
            if not (1 <= l <= 127) or p + 1 + l > names_end:
                continue
            # 先用 markers 的前几项做便宜校验：第 i*256 条也必须以合法长度字节开头
            ok = True
            for i in range(1, min(k, 16)):
                q = s + mk[i]
                if q >= names_end or not (1 <= buf[q] <= 127):
                    ok = False
                    break
            if ok:
                hits.append(s)
        good = []
        for s in hits:
            n = self._count_names(s, names_end)
            if n and ((k - 1) * 256 < n <= k * 256):
                good.append((s, n))
        if not good:
            raise KsymError("names 起点对不上 markers（候选 %d 个全部解析失败）" % len(hits))
        if len(good) > 1:
            # 多个解时要求 markers 每一个都对得上
            strict = []
            for s, n in good:
                ok = True
                for i in range(1, min(k, 64)):
                    p = s + mk[i]
                    if p >= names_end or not (1 <= buf[p] <= 127):
                        ok = False
                        break
                if ok:
                    strict.append((s, n))
            if strict:
                good = strict
        s, n = good[0]
        if log:
            log("  names @ 0x%X  条数 %d  长 %d" % (s, n, names_end - s))
        return s, n, names_end

    def _count_names(self, start, end):
        """
        从 start 逐条解析到 end，返回条数。

        names 之后到 markers 之间会有一小段全 0 的对齐 padding（本机型 240 字节），
        遇到全 0 尾巴就算正常结束 —— 一定要判这一条，否则整条链在这里断掉。
        """
        buf = self.buf
        p = start
        n = 0
        while p < end:
            l = buf[p]
            if l == 0:
                if n and not any(buf[p:end]):
                    return n
                return None
            if l > 127:
                return None
            p += 1 + l
            n += 1
        return n if p == end else None

    # -- 5. offsets：names 之前的 int32 数组，长 N*4，非递减，首 0 -------
    def find_offsets(self, names_start, n, log=None):
        buf = self.buf
        need = n * 4
        for gap in range(0, 2049, 4):
            end = names_start - gap
            st = end - need
            if st < 0:
                break
            if _u32(buf, st, 1)[0] != 0:
                continue
            first8 = _u32(buf, st, 8)
            if any(first8[i] > first8[i + 1] for i in range(7)):
                continue
            last = _u32(buf, end - 4, 1)[0]
            if last < 4096 or last > MAX_OFFSET:
                continue
            a = _u32(buf, st, n)
            bad = 0
            prev = 0
            for v in a:
                if v < prev or v > MAX_OFFSET:
                    bad += 1
                    if bad > 2:
                        break
                prev = v
            if bad > 2:
                continue
            if a[-1] != last:
                continue
            if log:
                log("  offsets @ 0x%X  条数 %d  末项 0x%X" % (st, n, last))
            return st, list(a)
        return None, None

    # -- 6. 串起来 --------------------------------------------------------
    def locate(self, log=None):
        if self._offsets is not None:
            return self._layout
        self.check_arm64()
        if log:
            log("  镜像 %s  %d 字节" % (os.path.basename(self.path), self.size))
        ok = False
        for idx_off in self.find_token_index(log):
            t, toks = self.decode_table(idx_off, log)
            if t is None:
                continue
            mk_off, k = self.find_markers(t, log)
            if mk_off is None:
                continue
            ns, n, ne = self.find_names(mk_off, k, log)
            off_st, offs = self.find_offsets(ns, n, log)
            if off_st is None:
                continue
            self._toks = toks
            self._offsets = offs
            self._layout = dict(token_index=idx_off, token_table=t, markers=mk_off,
                                markers_k=k, names=ns, names_end=ne, count=n,
                                offsets=off_st)
            ok = True
            break
        if not ok:
            raise KsymError(
                "镜像里没找到完整的 kallsyms 表。可能原因：\n"
                "  · CONFIG_KALLSYMS 被关了（极少见，正常 Android 内核都开）\n"
                "  · 镜像被裁剪 / 加密过，.rodata 不完整\n"
                "  · 这不是内核 Image（先做一次 check_arm64）")
        return self._layout

    def symbols(self):
        """返回 {符号名: 偏移}，偏移 = 符号地址 − _text。类型字符已剥掉。"""
        self.locate()
        if self._names is None:
            buf = self.buf
            lay = self._layout
            names = []
            p = lay["names"]
            end = lay["names_end"]
            toks = self._toks
            while p < end:
                l = buf[p]
                p += 1
                s = b"".join([toks[b] for b in buf[p:p + l]])
                p += l
                names.append(s)
            self._names = names
        out = {}
        for i, raw in enumerate(self._names):
            if not raw:
                continue
            # kallsyms 每条前面有一个类型字符（t/T/d/D/b/B/r/R/a/A…），
            # 展开出来的第一个字符就是它，后面才是名字
            name = raw[1:].decode("latin1") if raw[:1].isalpha() else raw.decode("latin1")
            if not name:
                continue
            off = self._offsets[i]
            if name not in out or off < out[name]:
                out[name] = off
        return out

    def info(self):
        self.locate()
        return dict(self._layout, path=self.path, size=self.size)


def load(path, log=None):
    """一次性入口：给 Image 路径，返回 {符号: 偏移}。用完自动关闭。"""
    with ImageKallsyms(path) as ks:
        return ks.symbols()


if __name__ == "__main__":
    import sys
    import time
    p = sys.argv[1] if len(sys.argv) > 1 else r"E:/BOOX/out_dump/unpack_b/kernel"
    t0 = time.time()
    with ImageKallsyms(p) as ks:
        lay = ks.locate(log=print)
        syms = ks.symbols()
    dt = time.time() - t0
    print("\n符号 %d 个，耗时 %.2fs" % (len(syms), dt))
    for k in ("_text", "_stext", "start_kernel", "init_task", "prepare_kernel_cred",
              "commit_creds", "selinux_state"):
        if k in syms:
            print("  %-24s 0x%X" % (k, syms[k]))
