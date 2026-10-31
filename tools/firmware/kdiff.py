# -*- coding: utf-8 -*-
"""
四款（或多款）BOOX 固件的 boot 内核横向对照 + Image 逐字节差异。

  python kdiff.py A.zip B.zip C.zip ...

对每个包输出：linux_banner、Image 大小、header 字段、内嵌 IKCONFIG 的
关键项。之后两两比对 Image，给出「差异字节数 / 占比」。

为什么用 Image 而不是 boot.img 比：boot.img 里还含 ramdisk、dtb、AVB
footer，这些跟机型强相关，混进来会把内核本身的差异淹掉。这里只比
解压后的 arm64 Image（text+rodata+data+bss 全零段也在内，因为
image_size 已对齐）。

复杂度：每对 O(n)，n = min(两 Image 大小)。字节比对走
int.from_bytes(..) ^ int.from_bytes(..) 再一次 count(0)，
不用 Python 循环 —— 60 MB×6 对用循环要几分钟，这样是秒级。

payload.bin 会落盘（约 1.8 GB/包），处理完即删。
"""
import os
import struct
import sys
import tempfile
import zipfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fwpull
import kcheck

CHUNK = 32 << 20          # 32 MB：比整块内存占用可控，比小块少几次系统调用
WORK = os.path.join(os.path.dirname(os.path.abspath(__file__)), "_img")


def payload_from_zip(zpath):
    """zip 里的 payload.bin -> 临时文件。返回路径，调用方负责删。"""
    os.makedirs(WORK, exist_ok=True)
    tmp = os.path.join(WORK, os.path.basename(zpath) + ".payload.bin")
    if os.path.exists(tmp) and os.path.getsize(tmp) > (1 << 20):
        return tmp, False
    with zipfile.ZipFile(zpath) as z, z.open("payload.bin") as src, open(tmp, "wb") as dst:
        while True:
            b = src.read(16 << 20)
            if not b:
                break
            dst.write(b)
    return tmp, True


def boot_of(payload):
    """payload -> boot.img 字节"""
    with open(payload, "rb") as fp:
        ver, manifest, data_start = fwpull.read_payload_header(fp)
        bs, parts = fwpull.parse_manifest(manifest)
        if "boot" not in parts:
            raise SystemExit("  ! payload 里没有 boot 分区")
        tf = tempfile.NamedTemporaryFile(delete=False, suffix=".boot")
        tf.close()
        try:
            fwpull.extract(fp, data_start, parts["boot"], bs, open(tf.name, "wb"))
            with open(tf.name, "rb") as f:
                return f.read()
        finally:
            try:
                os.remove(tf.name)
            except OSError:
                pass


def facts(zpath):
    """把一个包拆成一组可对照的事实"""
    name = os.path.basename(zpath)
    print("=" * 78)
    print(name, flush=True)
    payload, created = payload_from_zip(zpath)
    try:
        img_boot = boot_of(payload)
    finally:
        if created:
            try:
                os.remove(payload)
            except OSError:
                pass

    kern, ki = fwpull.boot_kernel(img_boot)
    _tag, banner = fwpull.kernel_banner(kern)
    image, ctag = kcheck.load_image(kern)
    hdr = kcheck.img_header(image)
    cfg = kcheck.ikconfig(image)

    out = dict(
        zip=name,
        banner=banner,
        boot_len=len(img_boot),
        kernel_len=ki["kernel_size"],
        ctag=ctag,
        image_len=len(image),
        hdr=hdr,
        cfg=cfg if isinstance(cfg, dict) else None,
    )

    print(f"  banner   {banner}")
    print(f"  boot {len(img_boot):,} 字节   kernel {ki['kernel_size']:,} ({ctag})")
    print(f"  Image {len(image):,} 字节")
    if hdr:
        print(f"  header   text_offset=0x{hdr['text_offset']:x} image_size={hdr['image_size']:,} "
              f"flags=0x{hdr['flags']:x} 内核页={hdr['kernel_page']}")
    if out["cfg"] is None:
        print("  config   镜像里没有 IKCFG")
    else:
        for k in kcheck.WANT:
            v = out["cfg"].get(k)
            if v is not None:
                print(f"  {k}={v}")

    # Image 落盘，供后面的两两对比用（内存里留 4 份 60 MB 也没问题，
    # 但落盘后重跑不用再解一遍 zip）
    os.makedirs(WORK, exist_ok=True)
    ip = os.path.join(WORK, os.path.splitext(name)[0] + ".Image")
    with open(ip, "wb") as f:
        f.write(image)
    out["image_path"] = ip
    return out


def diff_pair(pa, pb, chunk=CHUNK):
    """返回 (差异字节数, 比对长度, a 长度, b 长度)"""
    na, nb = os.path.getsize(pa), os.path.getsize(pb)
    n = min(na, nb)
    diff = 0
    with open(pa, "rb") as fa, open(pb, "rb") as fb:
        while True:
            a = fa.read(chunk)
            if not a:
                break
            b = fb.read(chunk)
            # 两边长度不等：长的那个 chunk 要裁到和短的一边一样长，
            # 否则 XOR 结果超出 len(a) 字节，to_bytes 直接 OverflowError
            if len(b) > len(a):
                b = b[:len(a)]
            elif len(b) < len(a):
                b = b + b"\0" * (len(a) - len(b))   # 短的那边补零，尾部差异照算
            x = int.from_bytes(a, "big") ^ int.from_bytes(b, "big")
            diff += len(a) - x.to_bytes(len(a), "big").count(0)
    return diff, n, na, nb


def short(f):
    """banner 里取版本串：Linux version 4.19.157-xxx (…"""
    b = f["banner"] or ""
    s = b.split("Linux version ")[-1].split(" ")[0]
    return s


def main():
    zips = sys.argv[1:]
    if not zips:
        raise SystemExit(__doc__)
    fs = [facts(z) for z in zips]

    print()
    print("=" * 78)
    print("内核版本串")
    print("-" * 78)
    for f in fs:
        print(f"  {f['zip'][:44]:46s} {short(f)}")

    print()
    print("config 逐项（只列全体一致/不一致）")
    print("-" * 78)
    keys = [k for k in kcheck.WANT]
    for k in keys:
        vals = [f["cfg"].get(k) if f["cfg"] else None for f in fs]
        uniq = sorted(set(str(v) for v in vals))
        mark = "一致" if len(uniq) == 1 else "不同"
        print(f"  {mark}  {k:28s} {uniq[0] if len(uniq) == 1 else ' | '.join(uniq)}")

    print()
    print("=" * 78)
    print("Image 逐字节对比（差异字节 / 比对长度 = 占比）")
    print("-" * 78)
    rows = []
    for i in range(len(fs)):
        for j in range(i + 1, len(fs)):
            a, b = fs[i], fs[j]
            d, n, na, nb = diff_pair(a["image_path"], b["image_path"])
            pct = 100.0 * d / n if n else 0.0
            same = "同长度" if na == nb else f"{na:,} vs {nb:,}"
            print(f"  {short(a)[:26]:28s} vs {short(b)[:26]:28s} {d:>11,} / {n:>11,} = {pct:6.2f}%   {same}")
            rows.append((short(a), short(b), d, n, pct, na, nb))

    print()
    print("=" * 78)
    print("Markdown（直接贴进 README）")
    print("-" * 78)
    print("| A | B | 差异字节 | 比对长度 | 差异占比 |")
    print("|---|---|---:|---:|---:|")
    for a, b, d, n, pct, na, nb in rows:
        print(f"| `{a}` | `{b}` | {d:,} | {n:,} | {pct:.2f}% |")


if __name__ == "__main__":
    main()
