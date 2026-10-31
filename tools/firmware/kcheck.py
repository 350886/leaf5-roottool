# -*- coding: utf-8 -*-
"""
从 update.zip 里读 boot 的内核，输出能直接跟 target.h 对照的几种事实：

  * Image header 的 text_offset / image_size / flags（内核页大小）
  * linux_banner（版本串 + 编译时间）
  * 内嵌 config（CONFIG_IKCONFIG 开的时候才有）里的
    VA_BITS / VMAP_STACK / NR_CPUS / SLUB / KASAN ...

  python kcheck.py a.zip b.zip ...
"""
import gzip
import io
import os
import struct
import sys
import zipfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fwpull

WANT = [
    "CONFIG_ARM64_VA_BITS",
    "CONFIG_ARM64_PAGE_SHIFT",
    "CONFIG_VMAP_STACK",
    "CONFIG_NR_CPUS",
    "CONFIG_SLUB",
    "CONFIG_SLAB_FREELIST",
    "CONFIG_KASAN",
    "CONFIG_RANDOMIZE_BASE",
    "CONFIG_ARM64_SW_TTBR0_PAN",
    "CONFIG_HARDENED_USERCOPY",
    "CONFIG_FUTEX",
    "CONFIG_PREEMPT",
    "CONFIG_IKCONFIG",
]


def load_image(kern):
    """返回 (Image 字节, 压缩标签)"""
    if kern[:2] == b"\x1f\x8b":
        return gzip.decompress(kern), "gzip"
    if kern[:4] == b"\x28\xb5\x2f\xfd":
        import zstandard
        return zstandard.ZstdDecompressor().decompress(kern, max_output_size=1 << 30), "zstd"
    if kern[:4] == b"\x04\x22\x4d\x18":
        import lz4.frame
        return lz4.frame.decompress(kern), "lz4"
    return kern, "raw"


def img_header(img):
    if img[0x38:0x3c] != b"ARM\x64":
        return None
    text_off, image_size, flags = struct.unpack("<QQQ", img[0x08:0x20])
    page = {0: 4096, 2: 16384, 4: 65536}.get(flags & 0b110, None)
    return dict(text_offset=text_off, image_size=image_size, flags=flags,
                kernel_page=page, be=bool(flags & 1))


def ikconfig(img):
    i = img.find(b"IKCFG_ST")
    if i < 0:
        return None
    j = img.find(b"IKCFG_ED", i)
    if j < 0:
        return None
    try:
        raw = gzip.decompress(img[i + 8:j])
    except Exception as e:
        return f"<IKCFG 解压失败 {e}>"
    m = {}
    for line in raw.decode("utf-8", "replace").splitlines():
        if line.startswith("CONFIG_"):
            k, _, v = line.partition("=")
            m[k] = v
    return m


def one(zpath):
    name = os.path.basename(zpath)
    print("=" * 78)
    print(name)
    tmp = os.path.splitext(zpath)[0] + ".payload.bin"
    if not os.path.exists(tmp) or os.path.getsize(tmp) == 0:
        print("  解压 payload.bin …", flush=True)
        with zipfile.ZipFile(zpath) as z, z.open("payload.bin") as src, open(tmp, "wb") as dst:
            while True:
                b = src.read(16 << 20)
                if not b:
                    break
                dst.write(b)
    try:
        with open(tmp, "rb") as fp:
            ver, manifest, data_start = fwpull.read_payload_header(fp)
            bs, parts = fwpull.parse_manifest(manifest)
            if "boot" not in parts:
                print("  没有 boot 分区")
                return
            # fwpull.extract 收工时会把自己的输出流关掉，所以落临时文件再读回来
            import tempfile
            tf = tempfile.NamedTemporaryFile(delete=False, suffix=".boot")
            tf.close()
            try:
                fwpull.extract(fp, data_start, parts["boot"], bs, open(tf.name, "wb"))
                with open(tf.name, "rb") as f:
                    img_boot = f.read()
            finally:
                try:
                    os.remove(tf.name)
                except OSError:
                    pass
    finally:
        try:
            os.remove(tmp)
        except OSError:
            pass

    kern, kinfo = fwpull.boot_kernel(img_boot)
    print(f"  boot {len(img_boot):,} 字节   kernel {kinfo['kernel_size']:,}")
    tag, banner = fwpull.kernel_banner(kern)
    print(f"  banner  {banner}")
    image, ctag = load_image(kern)
    print(f"  kernel  {ctag} -> Image {len(image):,} 字节")
    h = img_header(image)
    if h:
        print(f"  header  text_offset=0x{h['text_offset']:x} image_size={h['image_size']:,} "
              f"flags=0x{h['flags']:x} 内核页={h['kernel_page']} BE={h['be']}")
    else:
        print("  header  不是 ARM64 Image（找不到 'ARM\\x64' 魔数）")
    cfg = ikconfig(image)
    if cfg is None:
        print("  config  镜像里没有 IKCFG（CONFIG_IKCONFIG 没开）")
    elif isinstance(cfg, str):
        print("  config ", cfg)
    else:
        for k in WANT:
            if k in cfg:
                print(f"  {k}={cfg[k]}")
            else:
                for kk in cfg:
                    if kk.startswith(k + "_") or kk == k:
                        print(f"  {kk}={cfg[kk]}")


def main():
    for p in sys.argv[1:]:
        one(p)


if __name__ == "__main__":
    main()
