#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""从 BOOX 的 update.zip / payload.bin 里提取指定分区, 并读内核版本串。

不依赖 payload-dumper-go: A/B OTA 的 payload 格式是公开的
(magic "CrAU" + protobuf manifest + 数据区), 这里用标准库直解。
支持 REPLACE / REPLACE_BZ / REPLACE_XZ / ZERO / DISCARD 五种操作 ——
全量包里只会出现这几种; 一旦见到 BSDIFF/SOURCE_COPY 说明拿到的是增量包,
直接报错而不是产出一个坏镜像。

用法:
    python fwpull.py -l xx_update.zip                    # 列分区
    python fwpull.py -p boot -o boot.img xx_update.zip   # 提 boot
    python fwpull.py -p boot --banner-only xx_update.zip # 只打内核版本串
"""
import argparse
import bz2
import lzma
import os
import struct
import sys
import zipfile

BLOCK = 4096


# ---------- 最小 protobuf 解码 ----------
def _varint(buf, i):
    r = s = 0
    while True:
        b = buf[i]
        i += 1
        r |= (b & 0x7F) << s
        if not b & 0x80:
            return r, i
        s += 7


def pb(buf):
    """解一层 message, 返回 {字段号: [值...]}。只解到需要的那层。"""
    out = {}
    i = 0
    n = len(buf)
    while i < n:
        key, i = _varint(buf, i)
        fn, wt = key >> 3, key & 7
        if wt == 0:
            v, i = _varint(buf, i)
        elif wt == 2:
            ln, i = _varint(buf, i)
            v = buf[i:i + ln]
            i += ln
        elif wt == 5:
            v = buf[i:i + 4]
            i += 4
        elif wt == 1:
            v = buf[i:i + 8]
            i += 8
        else:
            raise ValueError(f"未知 wire type {wt} @字段{fn}")
        out.setdefault(fn, []).append(v)
    return out


def _u64(b):
    # protobuf 里 uint64 走 varint, 解出来已经是 int; 只有定长字段才是 bytes
    if isinstance(b, int):
        return b
    return int.from_bytes(b, "big")


# ---------- payload 头 ----------
def read_payload_header(fp):
    magic = fp.read(4)
    if magic != b"CrAU":
        raise ValueError(f"不是 payload: magic={magic!r}")
    version = _u64(fp.read(8))
    manifest_size = _u64(fp.read(8))
    sig_size = 0
    if version >= 2:
        # v2 起 manifest 后面跟一段 metadata signature, 不计入 manifest_size
        sig_size = int.from_bytes(fp.read(4), "big")
    manifest = fp.read(manifest_size)
    fp.seek(sig_size, 1)
    return version, manifest, fp.tell()


def parse_manifest(manifest):
    m = pb(manifest)
    bs = _u64(m[3][0]) if 3 in m else BLOCK
    parts = {}
    for raw in m.get(13, []):
        p = pb(raw)
        name = p[1][0].decode()
        new_size = 0
        if 7 in p:                       # PartitionInfo.size
            pi = pb(p[7][0])
            new_size = _u64(pi[1][0]) if 1 in pi else 0
        ops = []
        for oraw in p.get(8, []):
            o = pb(oraw)
            typ = o[1][0]
            doff = _u64(o[2][0]) if 2 in o else 0
            dlen = _u64(o[3][0]) if 3 in o else 0
            exts = []
            for eraw in o.get(6, []):    # dst_extents
                e = pb(eraw)
                exts.append((_u64(e[1][0]), _u64(e[2][0])))
            ops.append((typ, doff, dlen, exts))
        parts[name] = dict(size=new_size, ops=ops)
    return bs, parts


OPNAME = {0: "REPLACE", 1: "REPLACE_BZ", 2: "MOVE", 3: "BSDIFF", 4: "SOURCE_COPY",
          5: "SOURCE_BSDIFF", 6: "ZERO", 7: "DISCARD", 8: "REPLACE_XZ",
          9: "PUFFDIFF", 10: "BROTLI_BSDIFF"}


def extract(fp, data_start, part, block_size, out):
    """按 ops 重建分区。数据区里各 op 的 data_offset 是相对数据区起点的绝对偏移。"""
    size = part["size"] or max(
        (sb + nb) * block_size for _, _, _, exts in part["ops"] for sb, nb in exts)
    f = out if out else open(os.devnull, "wb")
    try:
        f.truncate(size)
        for typ, doff, dlen, exts in part["ops"]:
            name = OPNAME.get(typ, str(typ))
            if typ in (0, 1, 8):
                fp.seek(data_start + doff)
                blob = fp.read(dlen)
                if typ == 1:
                    blob = bz2.decompress(blob)
                elif typ == 8:
                    blob = lzma.decompress(blob)
            elif typ in (6, 7):
                blob = b""
            else:
                raise ValueError(f"遇到增量操作 {name}, 这不是全量包, 无法直接重建")
            pos = 0
            for sb, nb in exts:
                chunk_len = nb * block_size
                piece = blob[pos:pos + chunk_len]
                f.seek(sb * block_size)
                if typ in (6, 7):
                    f.write(b"\0" * chunk_len)     # ZERO/DISCARD 显式填零
                else:
                    f.write(piece)
                pos += chunk_len
        f.truncate(size)
        return size
    finally:
        if out:
            f.close()


# ---------- boot.img ----------
def boot_kernel(img):
    """从 boot.img 里取 kernel 字节。返回 (kernel_bytes, info)。

    v0-v2 的 header 里 img[8:12] 是 kernel_size，img[12:16] 是 kernel_addr
    （**加载地址，不是文件偏移**）。以前把它当偏移用，在 Leaf5 那种
    kernel_addr=0 的镜像上碰巧对，Tab8C/Tab8/Tab10 的 kernel_addr=0x8000
    就会切到 kernel 中间，解压出来是垃圾。kernel 永远紧跟 header 那一页。
    """
    if img[:8] != b"ANDROID!":
        raise ValueError(f"boot 头不是 ANDROID! 而是 {img[:8]!r}")
    kernel_size = struct.unpack("<I", img[8:12])[0]
    ramdisk_size = struct.unpack("<I", img[16:20])[0]
    page = struct.unpack("<I", img[36:40])[0] or 2048
    hdr_ver = struct.unpack("<I", img[40:44])[0]
    if hdr_ver >= 3:                    # v3+ 固定 4096 对齐
        page = 4096
    k_off = page
    info = dict(kernel_size=kernel_size, ramdisk_size=ramdisk_size,
                page_size=page, hdr_ver=hdr_ver, kernel_at=k_off)
    return img[k_off:k_off + kernel_size], info


def kernel_banner(kern):
    """内核镜像可能是 gzip / lz4 / zstd / 未压缩 Image, 都试一遍取 linux_banner。"""
    import gzip
    cands = []
    if kern[:2] == b"\x1f\x8b":
        try:
            cands.append(("gzip", gzip.decompress(kern)))
        except Exception as e:
            print(f"  ! gzip 解压失败: {e}")
    elif kern[:4] == b"\x04\x22\x4d\x18":
        try:
            import lz4.frame  # 可选依赖
            cands.append(("lz4", lz4.frame.decompress(kern)))
        except ImportError:
            print("  ! lz4 压缩的内核, 需要 pip install lz4")
        except Exception as e:
            print(f"  ! lz4 解压失败: {e}")
    elif kern[:4] == b"\x28\xb5\x2f\xfd":
        try:
            import zstandard  # 可选依赖
            cands.append(("zstd", zstandard.ZstdDecompressor().decompress(
                kern, max_output_size=512 << 20)))
        except ImportError:
            print("  ! zstd 压缩的内核, 需要 pip install zstandard")
        except Exception as e:
            print(f"  ! zstd 解压失败: {e}")
    else:
        cands.append(("raw", kern))
    for tag, data in cands:
        i = data.find(b"Linux version ")
        if i >= 0:
            j = data.find(b"\x00", i)
            return tag, data[i:j if j > 0 else i + 256].decode("utf-8", "replace")
    return (cands[0][0] if cands else "?"), None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("archive", help="update.zip 或 payload.bin")
    ap.add_argument("-l", "--list", action="store_true")
    ap.add_argument("-p", "--partition", default="")
    ap.add_argument("-o", "--out", default="")
    ap.add_argument("--banner-only", action="store_true", help="只打内核版本串, 不留 boot.img")
    ap.add_argument("--keep-payload", action="store_true")
    a = ap.parse_args()

    tmp_payload = None
    if a.archive.lower().endswith(".zip"):
        tmp_payload = os.path.splitext(a.archive)[0] + ".payload.bin"
        if not os.path.exists(tmp_payload) or os.path.getsize(tmp_payload) == 0:
            print(f"解压 payload.bin ({os.path.getsize(a.archive)/2**20:.0f} MiB zip) …")
            with zipfile.ZipFile(a.archive) as z:
                with z.open("payload.bin") as src, open(tmp_payload, "wb") as dst:
                    while True:
                        b = src.read(8 << 20)
                        if not b:
                            break
                        dst.write(b)
        path = tmp_payload
    else:
        path = a.archive

    with open(path, "rb") as fp:
        ver, manifest, data_start = read_payload_header(fp)
        bs, parts = parse_manifest(manifest)
        print(f"payload v{ver}  block={bs}  分区 {len(parts)} 个  数据区 @{data_start:,}")

        if a.list or not a.partition:
            for n, p in sorted(parts.items(), key=lambda kv: -kv[1]["size"]):
                print(f"  {n:22s} {p['size']:>14,} 字节  {p['size']/2**20:8.1f} MiB  "
                      f"{len(p['ops'])} ops")
        else:
            if a.partition not in parts:
                print(f"没有分区 {a.partition}; 可用: {', '.join(sorted(parts))}")
                return 2
            p = parts[a.partition]
            if a.banner_only:
                import tempfile
                tf = tempfile.NamedTemporaryFile(delete=False, suffix=".img")
                tf.close()
                try:
                    sz = extract(fp, data_start, p, bs, open(tf.name, "wb"))
                    with open(tf.name, "rb") as f:
                        img = f.read()
                    kern, info = boot_kernel(img)
                    print(f"{a.partition}: {sz:,} 字节  hdr_v{info['hdr_ver']} "
                          f"page {info['page_size']}  kernel {info['kernel_size']:,} 字节")
                    tag, banner = kernel_banner(kern)
                    if banner:
                        print(f"内核({tag}): {banner}")
                        print(f"内核版本: {banner.split()[2] if len(banner.split())>2 else '?'}")
                    else:
                        print("未找到 Linux version 串")
                finally:
                    os.unlink(tf.name)
            else:
                out = a.out or f"{a.partition}.img"
                with open(out, "wb") as f:
                    sz = extract(fp, data_start, p, bs, f)
                print(f"写出 {out}  {sz:,} 字节")

    if tmp_payload and not a.keep_payload:
        os.remove(tmp_payload)
        print(f"已删中间文件 {os.path.basename(tmp_payload)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
