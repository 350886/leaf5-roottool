"""Android A/B OTA 的 payload.bin 解析与分区提取（V1 版）。

和 V2 的 l5tk/core/payload.py 是同一份实现，差别只有异常类型：
V1 不挂包，用本文件里的 PayloadError，不引用 l5tk.core.errors。

为什么需要它：ONYX 的 abl 把 `fastboot flash` 裁掉了（实测
`remote: 'unknown command'`），写 boot 只剩 dd 与 EDL 两条路，而这两条
都要「正确的原厂 boot.img」。自己 dd 备份只对已 root 的机器成立 ——
没 root 的机器连 block device 都读不了。官方 update.zip 里的 payload.bin
就带着每个分区的完整镜像，这是唯一「没 root 也能拿到原厂 boot」的来源。

格式（chromiumos update_metadata.proto，full OTA）::

    "CrAU" | u64be version | u64be manifest_size
           | [u32be metadata_signature_size]   # 仅 version >= 2
           | manifest(protobuf) | signature | blobs...

data_offset 是相对 **blobs 起点**（manifest + signature 之后），不是文件开头。
"""

from __future__ import annotations

import bz2
import lzma
import os
import shutil
import struct
import tempfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterator


class PayloadError(Exception):
    """payload 解析 / 提取失败。message 直接给人看，hint 是下一步怎么办。"""

    def __init__(self, message: str, hint: str = ""):
        super().__init__(message)
        self.message = message
        self.hint = hint

    def render(self) -> str:
        return "%s\n  → %s" % (self.message, self.hint) if self.hint else self.message


PAYLOAD_MAGIC = b"CrAU"

# InstallOperation.Type（update_metadata.proto）
OP_REPLACE = 0
OP_REPLACE_BZ = 1
OP_MOVE = 2
OP_BSDIFF = 3
OP_SOURCE_COPY = 4
OP_SOURCE_BSDIFF = 5
OP_ZERO = 6
OP_DISCARD = 7
OP_REPLACE_XZ = 8
OP_PUFFDIFF = 9
OP_BROTLI_BSDIFF = 10
OP_ZUCCHINI = 11

OP_NAMES = {
    OP_REPLACE: "REPLACE",
    OP_REPLACE_BZ: "REPLACE_BZ",
    OP_MOVE: "MOVE",
    OP_BSDIFF: "BSDIFF",
    OP_SOURCE_COPY: "SOURCE_COPY",
    OP_SOURCE_BSDIFF: "SOURCE_BSDIFF",
    OP_ZERO: "ZERO",
    OP_DISCARD: "DISCARD",
    OP_REPLACE_XZ: "REPLACE_XZ",
    OP_PUFFDIFF: "PUFFDIFF",
    OP_BROTLI_BSDIFF: "BROTLI_BSDIFF",
    OP_ZUCCHINI: "ZUCCHINI",
}

# 这些类型要读「旧镜像」才能算出来 —— 只在增量 OTA 里出现。
# full OTA 里遇到它说明包不是全量的，硬解出来的镜像必然是坏的，直接报错。
INCREMENTAL_OPS = frozenset({
    OP_MOVE, OP_BSDIFF, OP_SOURCE_COPY, OP_SOURCE_BSDIFF,
    OP_PUFFDIFF, OP_BROTLI_BSDIFF, OP_ZUCCHINI,
})

Progress = Callable[[int, int, str], None]


# ---------------------------------------------------------------- protobuf --
def _varint(buf: bytes, i: int) -> tuple[int, int]:
    """读一个 varint，返回 (值, 新位置)。protobuf 里长度也走 varint。"""
    shift = 0
    val = 0
    n = len(buf)
    while True:
        if i >= n:
            raise PayloadError("payload manifest 截断（varint 越界）",
                             hint="update.zip 没下完，或文件被改过")
        b = buf[i]
        i += 1
        val |= (b & 0x7F) << shift
        if not b & 0x80:
            return val, i
        shift += 7
        if shift > 63:
            raise PayloadError("payload manifest 里有非法 varint（超过 64 位）")


def _fields(buf: bytes) -> Iterator[tuple[int, int, int, int]]:
    """遍历一层 protobuf，产出 (字段号, wire_type, 值起点, 值终点)。

    wire type: 0=varint 1=64bit 2=length-delimited 5=32bit。
    3/4（已废弃的 group）与其它值一律报错 —— 静默跳过会让后面的偏移全错。
    """
    i = 0
    n = len(buf)
    while i < n:
        key, i = _varint(buf, i)
        fno = key >> 3
        wt = key & 7
        if fno == 0:
            raise PayloadError("payload manifest 字段号为 0（不合法）")
        if wt == 0:
            _, j = _varint(buf, i)
            yield fno, wt, i, j
            i = j
        elif wt == 2:
            ln, j = _varint(buf, i)
            if j + ln > n:
                raise PayloadError("payload manifest 字段 %d 越界（要 %d 字节）" % (fno, ln))
            yield fno, wt, j, j + ln
            i = j + ln
        elif wt == 5:
            if i + 4 > n:
                raise PayloadError("payload manifest 字段 %d 截断（fixed32）" % fno)
            yield fno, wt, i, i + 4
            i += 4
        elif wt == 1:
            if i + 8 > n:
                raise PayloadError("payload manifest 字段 %d 截断（fixed64）" % fno)
            yield fno, wt, i, i + 8
            i += 8
        else:
            raise PayloadError("payload manifest 里 wire type=%d 不认识" % wt)


def _u(buf: bytes, s: int) -> int:
    """读一个 varint 标量（调用点已经在 _fields 里定位到 s）。"""
    v, _ = _varint(buf, s)
    return v


@dataclass
class Op:
    """一条安装操作。full OTA 里就是「把这段数据解压后写到目标的某处」。"""

    type: int
    data_offset: int = 0
    data_length: int = 0
    # dst_extents: [(起始块, 块数)]，块大小取 manifest.block_size
    extents: list[tuple[int, int]] = field(default_factory=list)

    @property
    def name(self) -> str:
        return OP_NAMES.get(self.type, "OP_%d" % self.type)

    @property
    def incremental(self) -> bool:
        return self.type in INCREMENTAL_OPS


@dataclass
class Partition:
    name: str
    ops: list[Op] = field(default_factory=list)
    size: int = 0            # new_partition_info.size，0 = 包里没写

    @property
    def data_bytes(self) -> int:
        """要读的压缩数据量，进度条用这个，不用解压后的大小。"""
        return sum(o.data_length for o in self.ops)

    def describe(self) -> str:
        kinds = sorted({o.name for o in self.ops})
        return "%s：%d 段，数据 %.1f MB，目标 %.1f MB（%s）" % (
            self.name, len(self.ops), self.data_bytes / 1048576.0,
            self.size / 1048576.0 if self.size else 0.0, "/".join(kinds))


def _parse_extent(chunk: bytes) -> tuple[int, int]:
    """Extent { start_block = 1, num_blocks = 2 }。

    注意：这个函数拿到的 chunk 就是「这一层的完整字节」，
    里面所有偏移都是相对 chunk 的 —— 子层一律重新切成独立 bytes 再解，
    不要拿父 buffer 的绝对偏移去读子层（会错位成天文数字）。
    """
    start = nblk = 0
    for fno, wt, s, _e in _fields(chunk):
        if wt != 0:
            continue
        if fno == 1:
            start = _u(chunk, s)
        elif fno == 2:
            nblk = _u(chunk, s)
    return start, nblk


def _parse_op(chunk: bytes) -> Op:
    op = Op(type=-1)
    for fno, wt, s, e in _fields(chunk):
        if wt == 0:
            if fno == 1:
                op.type = _u(chunk, s)
            elif fno == 2:
                op.data_offset = _u(chunk, s)
            elif fno == 3:
                op.data_length = _u(chunk, s)
        elif wt == 2 and fno == 6:      # dst_extents，repeated Extent
            op.extents.append(_parse_extent(chunk[s:e]))
    if op.type < 0:
        raise PayloadError("payload 里有一条 InstallOperation 没有 type 字段")
    return op


def _parse_partition(chunk: bytes) -> Partition:
    part = Partition(name="")
    for fno, wt, s, e in _fields(chunk):
        if wt != 2:
            continue
        if fno == 1:
            part.name = chunk[s:e].decode("utf-8", "replace")
        elif fno == 8:                      # operations，repeated message
            part.ops.append(_parse_op(chunk[s:e]))
        elif fno == 7:                      # new_partition_info { size = 1 }
            info = chunk[s:e]
            for f2, w2, s2, _e2 in _fields(info):
                if f2 == 1 and w2 == 0:
                    part.size = _u(info, s2)
    return part


@dataclass
class Manifest:
    block_size: int = 4096
    partitions: list[Partition] = field(default_factory=list)
    minor_version: int = 0

    def by_name(self, name: str) -> Partition | None:
        for p in self.partitions:
            if p.name == name:
                return p
        return None


def parse_manifest(buf: bytes) -> Manifest:
    man = Manifest()
    for fno, wt, s, e in _fields(buf):
        if fno == 3 and wt == 0:            # block_size
            man.block_size = _u(buf, s) or 4096
        elif fno == 12 and wt == 0:         # minor_version
            man.minor_version = _u(buf, s)
        elif fno == 13 and wt == 2:         # partitions
            man.partitions.append(_parse_partition(buf[s:e]))
    if not man.partitions:
        raise PayloadError("payload manifest 里没有任何分区",
                         hint="不是 A/B OTA 包，或者包是增量版")
    return man


# ------------------------------------------------------------ 可 seek 切片 --
class _Slice:
    """把「zip 里 STORED 的 payload.bin」当成一个独立文件来读。

    为什么不用 zipfile 的 open()：payload.bin 平均 1.8 GB，
    ZipExtFile 对 STORED 虽然能 seek，但每次都要重走一遍 header 判断；
    而我们只需要「从 data_start 起的一段连续字节」，直接用底层文件句柄
    按绝对偏移读，省掉一层封装，也省掉 1.8 GB 的解压缓冲。
    """

    def __init__(self, path: str | Path, start: int, size: int):
        self._fh = open(path, "rb")
        self.start = start
        self.size = size

    def read_at(self, off: int, n: int) -> bytes:
        if off < 0 or n < 0 or off + n > self.size:
            raise PayloadError(
                "payload 读取越界：off=%d n=%d size=%d" % (off, n, self.size),
                hint="update.zip 不完整（截断），重新下载")
        self._fh.seek(self.start + off)
        data = self._fh.read(n)
        if len(data) != n:
            raise PayloadError("payload 读取不满：要 %d 字节只拿到 %d" % (n, len(data)),
                             hint="文件被截断")
        return data

    def close(self) -> None:
        try:
            self._fh.close()
        except OSError:
            pass


def _zip_payload_offset(z: zipfile.ZipFile, info: zipfile.ZipInfo) -> int:
    """算 payload.bin 在 zip 文件里的真实数据起点。

    zip 的 local file header 长度可变（文件名 + extra field），
    ZipInfo.header_offset 指的是 header 起点，不是数据起点。
    """
    with open(z.filename, "rb") as f:
        f.seek(info.header_offset)
        hdr = f.read(30)
    if len(hdr) < 30 or hdr[:4] != b"PK\x03\x04":
        raise PayloadError("update.zip 的 local header 坏了（offset=%d）"
                         % info.header_offset, hint="重新下载固件包")
    nlen, elen = struct.unpack("<HH", hdr[26:30])
    return info.header_offset + 30 + nlen + elen


class Payload:
    """一个 payload.bin（或含它的 update.zip）。

    用法::

        p = Payload("update.zip")
        print(p.manifest.partitions)      # 有哪些分区
        p.extract("boot", "boot_stock.img")

    析构会关句柄；但 Windows 上长生命周期对象建议显式 close()，
    否则重命名/删除 update.zip 会被占用。
    """

    def __init__(self, path: str | Path, entry: str = "payload.bin"):
        self.path = Path(path)
        self.entry = entry
        self._slice: _Slice | None = None
        self._tmp: str = ""
        self._zip: zipfile.ZipFile | None = None
        self.manifest = Manifest()
        self.blob_start = 0
        self.version = 0
        self._open()

    # -- 打开 -------------------------------------------------------------
    def _open(self) -> None:
        if not self.path.is_file():
            raise PayloadError("找不到固件包：%s" % self.path,
                             hint="用 --ota 指定 update.zip，或把包放进 firmware\\")
        if self.path.suffix.lower() == ".upx":
            raise PayloadError(
                "%s 是 ONYX 的加密容器，不能直接读" % self.path.name,
                hint="先在设备/官方工具里解成同一份 update.zip（包内应有 payload.bin）")
        if zipfile.is_zipfile(self.path):
            self._open_zip()
        else:
            self._slice = _Slice(self.path, 0, self.path.stat().st_size)
        self._read_header()

    def _open_zip(self) -> None:
        z = zipfile.ZipFile(self.path)
        try:
            info = z.getinfo(self.entry)
        except KeyError:
            names = [n for n in z.namelist() if n.endswith(".bin")][:6]
            z.close()
            raise PayloadError(
                "%s 里没有 %s" % (self.path.name, self.entry),
                hint="包内大文件：%s" % (", ".join(names) or "（无）"))
        self._zip = z
        if info.compress_type == zipfile.ZIP_STORED:
            start = _zip_payload_offset(z, info)
            self._slice = _Slice(self.path, start, info.file_size)
        else:
            # DEFLATED：OTA 里罕见（没法流式写），落到临时文件再读。
            # 1.8 GB 落盘是代价，但比在内存里留 1.8 GB 强。
            fd, tmp = tempfile.mkstemp(prefix="l5tk_payload_", suffix=".bin")
            os.close(fd)
            with z.open(info) as src, open(tmp, "wb") as dst:
                shutil.copyfileobj(src, dst, 8 << 20)
            self._tmp = tmp
            self._slice = _Slice(tmp, 0, os.path.getsize(tmp))

    def _read_header(self) -> None:
        s = self._slice
        assert s is not None
        head = s.read_at(0, 20)
        if head[:4] != PAYLOAD_MAGIC:
            raise PayloadError(
                "payload.bin 魔数不对：%r（应为 %r）" % (head[:4], PAYLOAD_MAGIC),
                hint="这不是 A/B OTA 的 payload，可能是别的格式")
        self.version, msz = struct.unpack(">QQ", head[4:20])
        if self.version not in (1, 2):
            raise PayloadError("payload 版本 %d 不认识（只支持 1 / 2）" % self.version)
        hdr = 20
        sig_size = 0
        if self.version >= 2:
            sig_size = struct.unpack(">I", s.read_at(20, 4))[0]
            hdr = 24
        if msz == 0 or msz > s.size:
            raise PayloadError("payload manifest 长度异常：%d（文件 %d 字节）"
                             % (msz, s.size), hint="update.zip 不完整")
        man = s.read_at(hdr, msz)
        self.manifest = parse_manifest(man)
        self.blob_start = hdr + msz + sig_size

    # -- 查询 -------------------------------------------------------------
    def partitions(self) -> dict[str, Partition]:
        return {p.name: p for p in self.manifest.partitions}

    def names(self) -> list[str]:
        return [p.name for p in self.manifest.partitions]

    def find_boot(self) -> Partition | None:
        """按优先级挑「该打补丁的那个」分区。

        Android 13 起，Magisk 的补丁目标从 boot 移到了 init_boot
        （kernel 留在 boot，ramdisk 单独拆走）。两个都在时**必须**打
        init_boot —— 打 boot 会得到一个没 ramdisk 的镜像，刷上去直接不进系统。
        """
        for n in ("init_boot", "boot"):
            p = self.manifest.by_name(n)
            if p is not None:
                return p
        return None

    # -- 提取 -------------------------------------------------------------
    def extract(self, name: str, out: str | Path,
                progress: Progress | None = None) -> dict:
        """把分区还原成裸镜像写到 out，返回统计信息。

        写之前先落 .part 临时文件，成功才 rename —— 中途 Ctrl-C 或磁盘满
        不会留下一个「看起来像 boot.img 但只有一半」的文件被误刷。
        """
        part = self.manifest.by_name(name)
        if part is None:
            raise PayloadError(
                "payload 里没有分区 %s" % name,
                hint="可用分区：%s" % ", ".join(self.names()[:20]))
        if not part.ops:
            raise PayloadError("分区 %s 没有任何操作（空分区）" % name)

        bad = [o for o in part.ops if o.incremental]
        if bad:
            raise PayloadError(
                "分区 %s 用了增量操作 %s，这不是全量包"
                % (name, "/".join(sorted({o.name for o in bad}))),
                hint="增量 OTA 必须有旧镜像才能算出新镜像；换官方全量包")

        out = Path(out)
        out.parent.mkdir(parents=True, exist_ok=True)
        tmp = out.with_suffix(out.suffix + ".part")
        blk = self.manifest.block_size or 4096

        total = part.data_bytes
        done = 0
        written = 0
        # 只有一个 op 时不必按 extents 定位，直接顺序写；多个 op 且都带
        # extents 时按目标偏移写（LZ4DIFF 那类包会这样）。
        use_extents = bool(part.ops) and all(o.extents for o in part.ops)
        try:
            with open(tmp, "wb") as w:
                for op in part.ops:
                    if use_extents:
                        pos = op.extents[0][0] * blk
                        w.seek(pos)
                    if op.type in (OP_ZERO, OP_DISCARD):
                        # ZERO / DISCARD 的目标是一段全零，没有数据可读；
                        # 长度只能从 dst_extents 推。没有 extents 就无从下手，
                        # 让它按 0 字节过去，别假装写成功。
                        nblk = sum(c for _s, c in op.extents) if op.extents else 0
                        n = nblk * blk
                        if n:
                            zero = b"\0" * min(n, 1 << 20)
                            left = n
                            while left > 0:
                                w.write(zero[:min(left, len(zero))])
                                left -= min(left, len(zero))
                            written += n
                        done += op.data_length
                        if progress:
                            progress(done, total, "填零 %d 块" % nblk)
                        continue

                    raw = self._slice.read_at(self.blob_start + op.data_offset,
                                              op.data_length) if op.data_length else b""
                    if op.type == OP_REPLACE:
                        chunk = raw
                    elif op.type == OP_REPLACE_BZ:
                        chunk = bz2.decompress(raw)
                    elif op.type == OP_REPLACE_XZ:
                        chunk = lzma.decompress(raw)
                    else:
                        raise PayloadError(
                            "分区 %s 有未支持的操作 %s" % (name, op.name),
                            hint="只支持 REPLACE / REPLACE_BZ / REPLACE_XZ / ZERO")
                    w.write(chunk)
                    written += len(chunk)
                    done += op.data_length
                    if progress:
                        progress(done, total, op.name)
                w.flush()
                os.fsync(w.fileno())
                size = w.tell()
            if part.size and size < part.size:
                # 允许尾部为零（extents 没覆盖到的块本来就是零），但截断太多
                # 说明解析错了，别把这个文件交出去。
                raise PayloadError(
                    "分区 %s 解出来 %d 字节，manifest 声明 %d 字节（差 %d）"
                    % (name, size, part.size, part.size - size),
                    hint="payload 解析异常；换一份固件包或换用 dd 备份的 boot")
            os.replace(tmp, out)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

        return {
            "partition": name,
            "path": str(out),
            "bytes": out.stat().st_size,
            "ops": len(part.ops),
            "declared": part.size,
        }

    def extract_boot(self, out_dir: str | Path,
                     progress: Progress | None = None) -> dict:
        """抽「要打补丁的那个 boot」，文件名带上分区名，免得混淆。"""
        part = self.find_boot()
        if part is None:
            raise PayloadError(
                "固件包里既没有 init_boot 也没有 boot",
                hint="可用分区：%s" % ", ".join(self.names()[:20]))
        out = Path(out_dir) / ("%s_stock.img" % part.name)
        info = self.extract(part.name, out, progress=progress)
        info["is_init_boot"] = part.name == "init_boot"
        return info

    # -- 收尾 -------------------------------------------------------------
    def close(self) -> None:
        if self._slice:
            self._slice.close()
            self._slice = None
        if self._zip:
            try:
                self._zip.close()
            except OSError:
                pass
            self._zip = None
        if self._tmp:
            try:
                os.unlink(self._tmp)
            except OSError:
                pass
            self._tmp = ""

    def __enter__(self) -> "Payload":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def __repr__(self) -> str:
        return "<Payload %s v%d %d partitions>" % (
            self.path.name, self.version, len(self.manifest.partitions))


def find_ota(folder: str | Path) -> list[Path]:
    """在目录里找 update.zip，按体积倒序（固件包必然最大）。

    只认 .zip：ONYX 下载下来的是 .upx，那是厂商自己的加密容器
    （随机字节开头，没有可识别的魔数），要先解成 zip 才能读。
    把 .upx 也列出来只会让人以为工具坏了。
    """
    folder = Path(folder)
    if not folder.is_dir():
        return []
    out = [p for p in folder.iterdir()
           if p.is_file() and p.suffix.lower() == ".zip"]
    return sorted(out, key=lambda p: p.stat().st_size, reverse=True)
