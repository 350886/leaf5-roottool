# -*- coding: utf-8 -*-
"""
EDL 写分区的离线测试：不连 9008、不碰真设备，只验会话层的判断逻辑。

要覆盖的几条，都是「错一点就会刷砖」的地方：
  1. 分区名写错 → 必须报错并给出相近的名字，不能默默返回 False
  2. 镜像比分区的容量大 → 必须拒绝，且一字节都没发出去
  3. 正常路径 → 必须真的走到 handle_firehose("w")
  4. 读回 sha256 不符 → 必须用备份回写，然后抛异常说清「已回滚」
  5. 备份长度不足 → 必须在写入之前中止（没有可信备份就不许写）

跑法：python _test_dump/test_edl_write.py
"""
import hashlib
import os
import sys
import tempfile
import traceback

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import edlman
import edllink

OK = 0
BAD = 0


def chk(cond, msg):
    global OK, BAD
    if cond:
        OK += 1
        print("  [ok] %s" % msg)
    else:
        BAD += 1
        print("  [!!] %s" % msg)


GPT_TEXT = """\
Parsing Lun 0 GPT
  boot_a:              Offset 0x0000000000001000, Length 0x0000000006000000, Active False
  boot_b:              Offset 0x0000000006002000, Length 0x0000000006000000, Active True
  vbmeta_a:            Offset 0x000000000C003000, Length 0x0000000000010000, Active False
  super:               Offset 0x0000000010004000, Length 0x0000000060000000, Active False
"""


# ---------------------------------------------------------------- 假 firehose
class FakeFirehose:
    class cfg:
        SECTOR_SIZE_IN_BYTES = 512


class FakeFH:
    """只提供 Session.write 用得到的两样东西：扇区大小、handle_firehose。"""

    firehose = FakeFirehose

    def __init__(self):
        self.calls = []

    def handle_firehose(self, cmd, options):
        self.calls.append((cmd, options.get("<partitionname>"),
                           options.get("<filename>")))
        return True


def make_session(gpt=GPT_TEXT, ret=True):
    """造一个不碰 USB 的 Session：open() 不跑，fh/options 直接塞进去。"""
    s = edllink.Session.__new__(edllink.Session)
    s.fh = FakeFH()
    s.options = {"--lun": None, "<partitionname>": None, "<filename>": None}
    s.loader = "fake.bin"

    def fake_printgpt(on_line=None, on_progress=None, timeout=120):
        if on_line:
            for line in gpt.splitlines():
                on_line(line)
        return True

    s.printgpt = fake_printgpt
    if not ret:
        s.fh.handle_firehose = lambda cmd, opt: False
    return s


def tmpimg(n, pattern=b"\xA5"):
    fd, p = tempfile.mkstemp(suffix=".img")
    with os.fdopen(fd, "wb") as f:
        f.write(pattern * n)
    return p


# ---------------------------------------------------------------- 1. GPT 解析
def t_parse():
    print("[1] GPT 解析（parse_gpt 现在住在 edllink）")
    g = edllink.parse_gpt(GPT_TEXT)
    chk(set(g) == {"boot_a", "boot_b", "vbmeta_a", "super"},
        "解析出 4 个分区：%s" % sorted(g))
    chk(g["boot_b"]["active"] is True, "boot_b Active=True")
    chk(g["boot_a"]["active"] is False, "boot_a Active=False")
    chk(g["boot_b"]["offset"] == 0x6002000, "boot_b offset=0x6002000")
    chk(edlman.parse_gpt is edllink.parse_gpt, "edlman.parse_gpt 是同一个函数")
    chk(edlman.GPT_RE is edllink.GPT_RE, "GPT_RE 也是同一个对象")


# ----------------------------------------------------------- 2. 分区名写错
def t_missing_part():
    print("[2] 分区名写错：报错 + 给相近名字，且不发写命令")
    s = make_session()
    p = tmpimg(4096)
    try:
        s.write("bootb", p)
        chk(False, "应该抛 EdlError，实际没抛")
    except edllink.EdlError as e:
        msg = str(e)
        chk("分区表里没有 bootb" in msg, "错误里点名了分区：%s" % msg[:40])
        chk("boot" in msg, "给了相近分区名")
    chk(s.fh.calls == [], "没有发出任何写命令")
    os.remove(p)


# --------------------------------------------------------- 3. 镜像超容量
def t_oversize():
    print("[3] 镜像比分区的容量大：拒绝，且不发写命令")
    s = make_session()
    # boot_b 是 0x6000000 = 96MB；造一个 97MB 的（稀疏，不占磁盘）
    p = os.path.join(tempfile.gettempdir(), "_big_edl_test.img")
    with open(p, "wb") as f:
        f.truncate(97 * 1024 * 1024)
    try:
        s.write("boot_b", p)
        chk(False, "应该抛 EdlError，实际没抛")
    except edllink.EdlError as e:
        msg = str(e)
        chk("大于分区" in msg or "大于分区".replace("于", "") in msg,
            "错误说明了容量不足：%s" % msg[:50])
        chk("已中止" in msg, "明确说了已中止")
    chk(s.fh.calls == [], "没有发出任何写命令")
    os.remove(p)


# --------------------------------------------------------------- 4. 正常写
def t_happy():
    print("[4] 正常路径：走到 handle_firehose('w')，参数对得上")
    s = make_session()
    p = tmpimg(8192)
    r = s.write("boot_b", p)
    chk(r["sectors"] == 16, "8192 字节 = 16 扇区，算出 %d" % r["sectors"])
    chk(len(s.fh.calls) == 1, "只发了一条命令")
    cmd, part, fname = s.fh.calls[0]
    chk(cmd == "w", "命令是 w")
    chk(part == "boot_b", "分区名透传正确")
    chk(os.path.abspath(fname) == os.path.abspath(p), "镜像路径是绝对路径")
    os.remove(p)


# -------------------------------------------------------- 5. 设备返回 False
def t_device_false():
    print("[5] 设备返回 False：抛错，不假装成功")
    s = make_session(ret=False)
    p = tmpimg(4096)
    try:
        s.write("boot_b", p)
        chk(False, "应该抛 EdlError")
    except edllink.EdlError as e:
        chk("失败" in str(e), "错误里带「失败」：%s" % str(e)[:40])
    os.remove(p)


# ------------------------------------------------------ 6. _sha256_prefix
def t_prefix_hash():
    print("[6] _sha256_prefix：只取前 N 字节")
    p = tmpimg(3000, b"\x01")
    with open(p, "ab") as f:
        f.write(b"\x02" * 500)          # 尾部多 500 字节
    want = hashlib.sha256(b"\x01" * 3000).hexdigest()
    got = edlman._sha256_prefix(p, 3000)
    chk(got == want, "前 3000 字节的 sha256 对得上（忽略尾部）")
    try:
        edlman._sha256_prefix(p, 9999)
        chk(False, "长度不够时应该抛错")
    except edlman.EdlError as e:
        chk("少了" in str(e), "长度不够会抛 EdlError")
    os.remove(p)


# ------------------------------------- 7/8. write_partition 的读回与回滚
class FakeSession:
    """顶替 edllink.Session，让 write_partition 走完整流程但不碰 USB。"""

    script = []          # 每次 read 要写成什么内容
    writes = []          # 记录 (part, image)
    backup_bytes = b""

    def __init__(self, loader=None):
        self.fh = FakeFH()
        self.n = 0

    def open(self, on_line=None, on_progress=None, timeout=90):
        return True

    def printgpt(self, on_line=None, on_progress=None, timeout=120):
        if on_line:
            for line in GPT_TEXT.splitlines():
                on_line(line)
        return True

    def read(self, part, out_path, on_line=None, on_progress=None,
             timeout=900, place=None, expect=None, chunk=0, attempts=0):
        data = FakeSession.script[self.n] if self.n < len(FakeSession.script) else b""
        self.n += 1
        with open(out_path, "wb") as f:
            f.write(data)
        return out_path

    def write(self, part, image, on_line=None, on_progress=None, timeout=1800):
        FakeSession.writes.append((part, os.path.abspath(image)))
        return dict(partition=part, size=os.path.getsize(image),
                    sectors=1, seconds=0.1)

    def reset(self, on_line=None, timeout=60):
        return True

    def close(self):
        pass


def with_fake_session(fn):
    real_session = edlman.edllink.Session
    real_ensure = edlman._ensure_edl
    real_find = edlman.find_loader
    edlman.edllink.Session = FakeSession
    edlman._ensure_edl = lambda log=None, allow_driver=True: True
    edlman.find_loader = lambda: "fake.bin"
    try:
        return fn()
    finally:
        edlman.edllink.Session = real_session
        edlman._ensure_edl = real_ensure
        edlman.find_loader = real_find
        FakeSession.script = []
        FakeSession.writes = []


def t_verify_ok():
    print("[7] 读回一致：verified=True，不回滚")
    src = tmpimg(4096, b"\xAB")
    body = open(src, "rb").read()

    def run():
        FakeSession.script = [b"\x00" * 0x6000000,     # 备份（原分区）
                              body + b"\x00" * (512 - len(body) % 512) if len(body) % 512 else body]
        out = tempfile.mkdtemp()
        r = edlman.write_partition("fake.bin", "boot_b", src, bak_dir=out,
                                   log=None, backup=True, verify=True)
        chk(r["verified"] is True, "verified=True")
        chk(r["rolled_back"] is False, "没有回滚")
        chk(len(FakeSession.writes) == 1, "只写了一次（没有回写备份）")
        chk(FakeSession.writes[0][1] == os.path.abspath(src), "写的是源镜像")
        chk(os.path.isfile(r["backup"]), "备份文件落地：%s" % os.path.basename(r["backup"]))
        chk(os.path.isfile(r["readback"]), "读回文件落地")

    with_fake_session(run)
    os.remove(src)


def t_verify_mismatch():
    print("[8] 读回不一致：用备份回写，然后抛异常说清已回滚")
    src = tmpimg(4096, b"\xCD")
    body = open(src, "rb").read()

    def run():
        # 第 1 次 read = 备份；第 2 次 read = 读回（内容故意不对）
        FakeSession.script = [b"\x11" * 0x6000000, b"\x22" * 6144]
        out = tempfile.mkdtemp()
        try:
            edlman.write_partition("fake.bin", "boot_b", src, bak_dir=out,
                                   log=None, backup=True, verify=True)
            chk(False, "读回不符时应该抛 EdlError")
        except edlman.EdlError as e:
            msg = str(e)
            chk("读回校验不符" in msg, "错误点名了读回校验")
            chk("回滚完成" in msg, "说明了已回滚：%s" % msg[:60])
            chk("备份回写" in msg or "回写" in msg, "提到了用备份回写")
        writes = FakeSession.writes
        chk(len(writes) == 2, "写了两次（源镜像 + 回滚），实际 %d 次" % len(writes))
        if len(writes) == 2:
            chk(writes[1][1] != writes[0][1], "第二次写的是备份而不是源镜像")
            chk("stock_boot_b_" in os.path.basename(writes[1][1]),
                "第二次写的是 stock_* 备份")

    with_fake_session(run)
    os.remove(src)


def t_backup_short():
    print("[9] 备份长度不对：写入之前就中止")
    src = tmpimg(4096, b"\xEE")

    def run():
        FakeSession.script = [b"\x00" * 4096]     # 备份只给了 4KB
        out = tempfile.mkdtemp()
        try:
            edlman.write_partition("fake.bin", "boot_b", src, bak_dir=out,
                                   log=None, backup=True, verify=True)
            chk(False, "备份长度不对应该抛错")
        except edlman.EdlError as e:
            chk("备份长度不对" in str(e), "错误点名了备份长度：%s" % str(e)[:40])
            chk("分区未改动" in str(e), "声明了分区未改动")
        chk(FakeSession.writes == [], "一次写都没发出去")

    with_fake_session(run)
    os.remove(src)


def t_no_backup():
    print("[10] --no-backup：跳过备份但仍然读回校验")
    src = tmpimg(2048, b"\x77")
    body = open(src, "rb").read()

    def run():
        FakeSession.script = [body]
        out = tempfile.mkdtemp()
        r = edlman.write_partition("fake.bin", "boot_b", src, bak_dir=out,
                                   log=None, backup=False, verify=True)
        chk(r["backup"] == "", "没有备份路径")
        chk(r["verified"] is True, "读回校验照样做")
        chk(len(FakeSession.writes) == 1, "只写一次")

    with_fake_session(run)
    os.remove(src)


def main():
    tests = [t_parse, t_missing_part, t_oversize, t_happy, t_device_false,
             t_prefix_hash, t_verify_ok, t_verify_mismatch, t_backup_short,
             t_no_backup]
    for t in tests:
        try:
            t()
        except Exception:
            global BAD
            BAD += 1
            print("  [!!] 用例抛了未预期异常：")
            traceback.print_exc()
    print("\n通过 %d 项，失败 %d 项" % (OK, BAD))
    return 0 if BAD == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
