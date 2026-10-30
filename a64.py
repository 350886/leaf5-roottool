"""
极简 ARM64 解码器 —— 只解适配需要的那几条指令。

不追求完整反汇编。需要的只有三件事：

  ① 找 current        —— mrs xN, sp_el0
  ② 读懂字段偏移      —— ldr xT, [xN, #imm]
  ③ 累加函数栈帧      —— stp x29,x30,[sp,#-N]!  /  sub sp,sp,#N

多解一条没用，少解一条就推不出 target.h 的那几个手工宏。
全部按 ARM ARM 的位域写死，不依赖 capstone / keystone：PyInstaller 打包
它们体积翻倍，还挑 Python 版本，而这里只需要认 24 个 bit 的 pattern。

所有立即数都返回**有符号**整数（stp 的 imm7 是负数，容易踩）。
"""

import struct

# ---------------------------------------------------------------------------
# 指令编码常量（ARMv8-A A64）
# ---------------------------------------------------------------------------
# STP <Xt>, <Xt2>, [<Xn|SP>, #<imm>]!     pre-index，函数序言第一句就是它
_STP_PRE = 0xA9800000
_STP_PRE_MASK = 0xFFC00000
# STP 带符号偏移（无写回）
_STP_OFF = 0xA9000000
# STP post-index
_STP_POST = 0xA8800000
# LDR <Xt>, [<Xn|SP>, #<imm>]   64 位无符号偏移
_LDR_X_OFF = 0xF9400000
# LDR <Wt>, [<Xn|SP>, #<imm>]   32 位无符号偏移
_LDR_W_OFF = 0xB9400000
# STR <Xt>, [<Xn|SP>, #<imm>]
_STR_X_OFF = 0xF9000000
# SUB <Xd|SP>, <Xn|SP>, #<imm>
_SUB_IMM = 0xD1000000
_SUB_IMM_MASK = 0xFF800000
# ADD <Xd|SP>, <Xn|SP>, #<imm>
_ADD_IMM = 0x91000000
_ADD_IMM_MASK = 0xFF800000
# MRS <Xt>, <sysreg>；sp_el0 那条的固定部分是 0xD5384100
_MRS_SP_EL0 = 0xD5384100
_MRS_MASK = 0xFFFFFFE0
# RET
_RET = 0xD65F03C0
# 分支
_B = 0x14000000
_B_MASK = 0xFC000000
_BL = 0x94000000


def _sext(v, bits):
    """取 bits 位有符号值。stp 的 imm7 是负的，按无符号读会得到 127 这种鬼值。"""
    sign = 1 << (bits - 1)
    return (v & (sign - 1)) - (v & sign)


def word_at(buf, off):
    """读一条指令。越界返回 None（函数末尾不一定是 ret，也会掉进数据）。"""
    if off < 0 or off + 4 > len(buf):
        return None
    return struct.unpack_from("<I", buf, off)[0]


# ---------------------------------------------------------------------------
# 单条指令解码
# ---------------------------------------------------------------------------
class Insn(object):
    __slots__ = ("addr", "word", "kind", "rd", "rn", "rt", "rt2", "imm")

    def __init__(self, addr, word, kind, rd=None, rn=None, rt=None,
                 rt2=None, imm=None):
        self.addr = addr
        self.word = word
        self.kind = kind      # 'stp_pre' 'stp_off' 'ldr_x' 'ldr_w' 'str_x'
                              # 'sub_imm' 'add_imm' 'mrs_current' 'ret' 'b' 'bl' '?'
        self.rd = rd
        self.rn = rn
        self.rt = rt
        self.rt2 = rt2
        self.imm = imm

    def __repr__(self):
        a = ["%s" % self.kind]
        for k in ("rd", "rn", "rt", "rt2"):
            v = getattr(self, k)
            if v is not None:
                a.append("%s=x%d" % (k, v))
        if self.imm is not None:
            a.append("imm=%d" % self.imm)
        return "<%#x %s>" % (self.addr, " ".join(a))


def decode(addr, w):
    if w is None:
        return Insn(addr, 0, "?")
    if (w & _MRS_MASK) == _MRS_SP_EL0:
        return Insn(addr, w, "mrs_current", rt=w & 0x1F)
    if (w & _STP_PRE_MASK) == _STP_PRE:
        # STP pre-index: imm7 在 bit[21:15]，Rt2 在 [14:10]，Rn 在 [9:5]，Rt 在 [4:0]
        imm = _sext((w >> 15) & 0x7F, 7) * 8
        return Insn(addr, w, "stp_pre", rt=w & 0x1F, rn=(w >> 5) & 0x1F,
                    rt2=(w >> 10) & 0x1F, imm=imm)
    if (w & _STP_PRE_MASK) == _STP_OFF:
        imm = _sext((w >> 15) & 0x7F, 7) * 8
        return Insn(addr, w, "stp_off", rt=w & 0x1F, rn=(w >> 5) & 0x1F,
                    rt2=(w >> 10) & 0x1F, imm=imm)
    if (w & _STP_PRE_MASK) == _STP_POST:
        imm = _sext((w >> 15) & 0x7F, 7) * 8
        return Insn(addr, w, "stp_post", rt=w & 0x1F, rn=(w >> 5) & 0x1F,
                    rt2=(w >> 10) & 0x1F, imm=imm)
    if (w & _STP_PRE_MASK) == _LDR_X_OFF:
        imm = ((w >> 10) & 0xFFF) * 8
        return Insn(addr, w, "ldr_x", rt=w & 0x1F, rn=(w >> 5) & 0x1F, imm=imm)
    if (w & _STP_PRE_MASK) == _STR_X_OFF:
        imm = ((w >> 10) & 0xFFF) * 8
        return Insn(addr, w, "str_x", rt=w & 0x1F, rn=(w >> 5) & 0x1F, imm=imm)
    if (w & _STP_PRE_MASK) == _LDR_W_OFF:
        imm = ((w >> 10) & 0xFFF) * 4
        return Insn(addr, w, "ldr_w", rt=w & 0x1F, rn=(w >> 5) & 0x1F, imm=imm)
    if (w & _SUB_IMM_MASK) == _SUB_IMM:
        # SUB (immediate) 的 imm12 可以左移 12 位（sh=1），这里两种都算
        sh = (w >> 22) & 1
        imm = ((w >> 10) & 0xFFF) << (12 if sh else 0)
        return Insn(addr, w, "sub_imm", rd=w & 0x1F, rn=(w >> 5) & 0x1F, imm=imm)
    if (w & _ADD_IMM_MASK) == _ADD_IMM:
        sh = (w >> 22) & 1
        imm = ((w >> 10) & 0xFFF) << (12 if sh else 0)
        return Insn(addr, w, "add_imm", rd=w & 0x1F, rn=(w >> 5) & 0x1F, imm=imm)
    if w == _RET:
        return Insn(addr, w, "ret")
    if (w & _B_MASK) == _B:
        imm = _sext(w & 0x3FFFFFF, 26) * 4
        return Insn(addr, w, "b", imm=imm)
    if (w & _B_MASK) == _BL:
        imm = _sext(w & 0x3FFFFFF, 26) * 4
        return Insn(addr, w, "bl", imm=imm)
    return Insn(addr, w, "?")


def disasm(buf, off, count, limit=None):
    """从 buf[off] 起解 count 条。limit 是绝对上限（别把后面的函数吃进来）。"""
    out = []
    for i in range(count):
        a = off + i * 4
        if limit is not None and a >= limit:
            break
        w = word_at(buf, a)
        if w is None:
            break
        out.append(decode(a, w))
    return out


# ---------------------------------------------------------------------------
# 三条推导规则
# ---------------------------------------------------------------------------
def find_frame_size(buf, func_off, scan=60):
    """
    推函数总栈帧：序言 'stp x29,x30,[sp,#-N]!' 的 N，加上后续还没被恢复的
    'sub sp,sp,#M'。

    为什么不能只看第一条：__arm64_sys_prctl 的第一条是 stp #-0x60，后面还有
    一条 sub sp,sp,#0x1a0 —— 真正的帧是 0x200。只看第一条会得出 0x60，
    栈上写 waiter 的位置就全错了。

    只扫到第一次 ret / 第一次无条件 b（尾调用），避免把 else 分支的帧算进来。
    返回 (总帧, 明细) 或 (None, [])。
    """
    total = 0
    detail = []
    for ins in disasm(buf, func_off, scan):
        if ins.kind in ("ret", "b"):
            break
        if ins.kind == "stp_pre" and ins.rn == 31:      # Rn=31 是 SP
            total += -ins.imm                            # imm 是负的
            detail.append(("stp_pre", -ins.imm))
        elif ins.kind == "sub_imm" and ins.rn == 31 and ins.rd == 31:
            total += ins.imm
            detail.append(("sub_sp", ins.imm))
        elif ins.kind == "add_imm" and ins.rn == 31 and ins.rd == 31:
            total -= ins.imm
            detail.append(("add_sp", ins.imm))
    return (total or None), detail


def find_current_fields(buf, func_off, scan=40):
    """
    从「读 current 的那条 mrs」之后，收集所有 [current + imm] 的 64 位读。

    commit_creds 的开头是：
        mrs x20, sp_el0            ← current
        ldr x19, [x20, #0x7d8]     ← task->real_cred
        ldr x8,  [x20, #0x7e0]     ← task->cred
    两个指针在 task_struct 里挨着，差 8 —— 这就是自证条件，
    差不是 8 说明这条规则不适用于这个内核，宁可返回空也不猜。
    """
    insns = disasm(buf, func_off, scan)
    reg = None
    offs = []
    for ins in insns:
        if ins.kind == "mrs_current":
            reg = ins.rt
            continue
        if reg is None:
            continue
        if ins.kind == "ldr_x" and ins.rn == reg:
            if ins.imm not in offs:
                offs.append(ins.imm)
        elif ins.kind in ("ret", "b"):
            break
    return offs


def derive_task_cred_off(buf, commit_creds_off):
    """
    推 task_struct.cred 的偏移。返回 (offset, 说明) 或 (None, 原因)。

    判据三条，全过才认：
      ① 出现在 mrs sp_el0 之后的 [current+#imm] 读
      ② 有一对 imm 和 imm+8 同时出现（real_cred 紧跟 cred）
      ③ 结果落在 0x400..0x1400（4.19 是 0x7e0，5.10 是 0x8xx，再大就是扫错了）
    """
    offs = find_current_fields(buf, commit_creds_off)
    if not offs:
        return None, "commit_creds 里没找到 [current+#imm] 形式的读"
    pair = None
    for a in offs:
        if (a + 8) in offs:
            pair = (a, a + 8)
            break
    if not pair:
        return None, "没找到相邻 8 字节的两个字段（real_cred/cred），字段列表 %s" % (
            ", ".join("%#x" % x for x in offs[:8]),)
    cred = pair[1]
    if not (0x400 <= cred <= 0x1400):
        return None, "推出来的 cred 偏移 %#x 不在合理范围，放弃" % cred
    return cred, "commit_creds: real_cred=%#x, cred=%#x" % pair


def derive_prctl_frame(buf, prctl_off):
    """推 __arm64_sys_prctl 的总帧。返回 (size, 明细) 或 (None, 原因)。"""
    total, detail = find_frame_size(buf, prctl_off)
    if not total:
        return None, "没读到栈分配指令"
    if total % 16:
        # aarch64 要求 SP 16 字节对齐，不是 16 的倍数说明累加错了
        return None, "帧 %#x 不是 16 的倍数，累加有误：%s" % (
            total, ", ".join("%s+%#x" % d for d in detail))
    if not (0x40 <= total <= 0x2000):
        return None, "帧 %#x 不在合理范围" % total
    return total, " + ".join("%s %#x" % d for d in detail)
