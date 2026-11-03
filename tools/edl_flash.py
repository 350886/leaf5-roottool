# -*- coding: utf-8 -*-
"""EDL 分区写入工具（Firehose program 通路）。

用法：
    # 只读校验：读分区，算 sha256，不写
    python edl_flash.py --part boot_b --check

    # 把镜像写进分区，写完自动回读校验
    python edl_flash.py --part boot_b --img boot.img

    # 幂等自测：读分区 -> 原样写回 -> 回读，用来验证写入通路是否可用
    python edl_flash.py --part misc --idempotent

    # 指定 programmer
    python edl_flash.py --part boot_b --img boot.img --loader ..\\assets\\lito_moto_fhprg.bin

退出码：0 成功，1 参数/环境错误，2 写入或校验失败，3 设备未进入 raw 接收态。

要点：
  * 块大小取自 device 自报的 MaxPayloadSizeToTargetInBytes（moto 版 1MB，
    实测 24.5 MB/s；op 版只有 16384，且带 Device verified failed 校验，不可用）
  * 每块必须确认 program 响应里 rawmode="true"，否则设备没进 raw 态，
    后续二进制会被当 XML 解析
  * 写完成响应必须是 ACK
"""
import argparse
import hashlib
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)                       # root-tool/
for p in (ROOT, os.path.join(ROOT, "edlclient"), os.path.dirname(ROOT)):
    if p not in sys.path:
        sys.path.insert(0, p)

import edllink   # noqa: E402
import edlman    # noqa: E402

DEFAULT_LOADER = os.path.join(ROOT, "assets", "lito_moto_fhprg.bin")


def log(*a):
    print(*a, flush=True)


def read_range(fh, ss, sector, total_sectors, chunk_sectors, progress=True):
    out = bytearray()
    done = 0
    while done < total_sectors:
        n = min(chunk_sectors, total_sectors - done)
        rsp = fh.cmd_read_buffer(0, sector + done, n, False)
        data = rsp.data if isinstance(rsp.data, (bytes, bytearray)) else b""
        if len(data) != n * ss:
            raise RuntimeError("读 %d 扇区只拿到 %d 字节" % (n, len(data)))
        out += data
        done += n
        if progress and (done % (chunk_sectors * 16) == 0 or done == total_sectors):
            log("  读 %6.2f / %6.2f MB" % (done * ss / 1048576.0, total_sectors * ss / 1048576.0))
    return bytes(out)


def write_chunk(fh, ss, sector, nsec, payload):
    xml = ('<?xml version="1.0" ?><data>\n<program SECTOR_SIZE_IN_BYTES="%d" '
           'num_partition_sectors="%d" physical_partition_number="0" start_sector="%d" />\n</data>'
           % (ss, nsec, sector))
    rsp = fh.xmlsend(xml, False)
    d = getattr(rsp, "data", None)
    rawmode = str((d.get("rawmode") if isinstance(d, dict) else "") or "").lower()
    if rawmode != "true":
        # 这是最关键的一道判据。rawmode!=true 时设备不会切进 raw 接收态，
        # 紧接着发的二进制会被当 XML 解析，报 "Failed to parse xml"。
        err = getattr(rsp, "error", None)
        body = d if isinstance(d, dict) else ""
        raise PermissionError("rawmode=%r error=%r resp=%r" % (rawmode, err, body))
    fh.cdc.write(payload)
    fh.cdc.write(b'')                # ZLP：告诉设备本块数据结束
    wd = bytes(fh.wait_for_data())
    if b'value="ACK"' not in wd:
        raise IOError("写完成响应异常: %r" % wd[:200])


def write_image(fh, ss, mp, sector, total_sectors, blob):
    chunk_sectors = max(1, mp // ss)
    nchunks = (total_sectors + chunk_sectors - 1) // chunk_sectors
    log("分块写：%d 块 × %d 字节（MaxPayload=%d）" % (nchunks, chunk_sectors * ss, mp))
    t0 = time.time()
    for i in range(nchunks):
        s = sector + i * chunk_sectors
        n = min(chunk_sectors, total_sectors - i * chunk_sectors)
        chunk = blob[i * chunk_sectors * ss: (i + 1) * chunk_sectors * ss]
        if len(chunk) < n * ss:                       # 末块补齐到扇区边界
            chunk += b"\x00" * (n * ss - len(chunk))
        write_chunk(fh, ss, s, n, chunk)
        if (i + 1) % 8 == 0 or i == nchunks - 1:
            log("  已写 %3d/%d 块  %.1fs" % (i + 1, nchunks, time.time() - t0))
    dt = time.time() - t0
    log("写完成 %.2fs  %.2f MB/s" % (dt, total_sectors * ss / 1048576.0 / max(dt, 1e-3)))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--part", required=True, help="分区名，如 boot_b / misc")
    ap.add_argument("--img", help="要写入的镜像文件")
    ap.add_argument("--loader", default=DEFAULT_LOADER, help="firehose programmer")
    ap.add_argument("--check", action="store_true", help="只读，算 sha256")
    ap.add_argument("--idempotent", action="store_true", help="读出原内容原样写回，验证通路")
    ap.add_argument("--no-verify", action="store_true", help="写完不回读校验")
    args = ap.parse_args()

    if not os.path.isfile(args.loader):
        log("找不到 programmer: %s" % args.loader)
        return 1
    if not (args.check or args.idempotent or args.img):
        log("要么 --check / --idempotent，要么给 --img")
        return 1

    if not edlman._has_edl_device():
        log("设备不在 9008，重启进入 ...")
        edlman.reboot_to_edl(log=log)
        time.sleep(1)

    sess = edllink.Session(loader=args.loader)
    rc = 1
    try:
        sess.open(timeout=120)
        sess._drop_bogus_vendor()
        fh = sess.fh.firehose
        ss = int(fh.cfg.SECTOR_SIZE_IN_BYTES) or 512
        mp = int(fh.cfg.MaxPayloadSizeToTargetInBytes) or 1048576
        log("会话 OK  MaxPayload=%d  SECTOR=%d  loader=%s" % (mp, ss, os.path.basename(args.loader)))

        buf = []
        sess.printgpt(on_line=buf.append, timeout=90)
        gpt = edllink.parse_gpt("\n".join(buf))
        if args.part not in gpt:
            log("分区表里没有 %s" % args.part)
            return 1
        off = gpt[args.part]["offset"]
        length = gpt[args.part]["length"]
        sector = off // ss
        total_sectors = length // ss
        log("%s: offset=0x%X  大小=%.2f MB (%d 扇区)"
            % (args.part, off, length / 1048576.0, total_sectors))

        chunk_read = min(2048, total_sectors)

        # ---- 只读 ----
        if args.check:
            t0 = time.time()
            blob = read_range(fh, ss, sector, total_sectors, chunk_read)
            dt = time.time() - t0
            log("读 %.2fs  %.2f MB/s" % (dt, len(blob) / 1048576.0 / max(dt, 1e-3)))
            log("sha256 = %s" % hashlib.sha256(blob).hexdigest())
            log("头 16 字节 = %s" % blob[:16].hex())
            return 0

        # ---- 准备要写的数据 ----
        if args.idempotent:
            log("幂等模式：先读原内容，再原样写回")
            blob = read_range(fh, ss, sector, total_sectors, chunk_read)
            write_sectors = total_sectors
        else:
            with open(args.img, "rb") as f:
                blob = f.read()
            if len(blob) > length:
                log("镜像 %d 字节超过分区 %d 字节，拒绝写入" % (len(blob), length))
                return 1
            # 只写镜像覆盖到的扇区，分区尾部保持原样（不补零、不越界）
            write_sectors = (len(blob) + ss - 1) // ss
            log("镜像 %d 字节 -> 写 %d 扇区" % (len(blob), write_sectors))
            if write_sectors < total_sectors:
                log("提示：分区还剩 %d 扇区保持原样" % (total_sectors - write_sectors))

        src_sha = hashlib.sha256(blob).hexdigest()
        log("待写数据 sha256 = %s" % src_sha)

        # ---- 写 ----
        try:
            write_image(fh, ss, mp, sector, write_sectors, blob)
        except PermissionError as e:
            log("!! 设备拒绝 program：%s" % e)
            log("   换一个 programmer 试：--loader <path>")
            return 3

        # ---- 回读校验 ----
        if not args.no_verify:
            t0 = time.time()
            back = read_range(fh, ss, sector, write_sectors, chunk_read)
            dt = time.time() - t0
            back_sha = hashlib.sha256(back[:len(blob)]).hexdigest()
            log("回读 %.2fs  sha256 = %s" % (dt, back_sha))
            if back_sha != src_sha:
                i = next((k for k in range(min(len(back), len(blob))) if back[k] != blob[k]), -1)
                log("!! 校验失败，首个差异偏移 %d (0x%X)" % (i, i))
                return 2
            log("校验通过")
        rc = 0
    finally:
        try:
            sess.reset()
            log("reset 完成")
        except Exception as ex:
            log("reset 失败：%s" % ex)
        try:
            sess.close()
        except Exception:
            pass
    return rc


if __name__ == "__main__":
    sys.exit(main())
