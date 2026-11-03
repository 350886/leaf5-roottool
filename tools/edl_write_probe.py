#!/usr/bin/env python3
"""EDL 写通路探测 —— 判断一颗 Firehose programmer 在当前设备上能不能写。

为什么需要这个工具
------------------
9008 会话能建立、能 printgpt、能读分区，**不代表能写**。
实测（BOOX Leaf5 / SM6350 / lito）：
  * 读：4.77 MB/s，读出的 96MB 与系统内 sha256 逐字节一致
  * 写：任何分区、任何 XML 属性组合，`program` 一律回
        ERROR: fm=0, ato=0
        ERROR: Device verified failed.
        <response value="ACK" rawmode="false" />
    rawmode=false 表示设备不进 raw 数据接收态，后续字节被当作 XML 解析，
    于是报 "Failed to parse xml, error at offset 4090, 4096"。
    此时上层退化成 3.6 秒/块、4.4KB/s 的假象 —— 其实一个字节都没写进去。

判断依据只有一条：**program 命令的响应里 rawmode 是不是 "true"**。
是，就能写；不是，就别浪费时间调块大小和 ZLP。

用法
----
  # 只读探测（安全，不写任何字节）
  python edl_write_probe.py

  # 指定 programmer 与目标分区
  python edl_write_probe.py --loader assets/lito_moto_fhprg.bin --part misc

  # 真写验证：把读到的 4KB 原样写回，再读回比对（幂等，分区内容不变）
  python edl_write_probe.py --write

退出码
------
  0  可写（rawmode=true，且 --write 时读回一致）
  2  只能读，不能写
  1  会话/参数错误
"""
import argparse
import hashlib
import os
import sys
import time

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
for p in (_ROOT, os.path.join(_ROOT, "edlclient")):
    if p not in sys.path:
        sys.path.insert(0, p)

import edllink  # noqa: E402
import edlman   # noqa: E402


def log(t=""):
    print(t, flush=True)


def as_text(rsp):
    d = getattr(rsp, "data", None)
    if isinstance(d, str):
        return d
    if d is None:
        return ""
    try:
        return bytes(d).decode("utf-8", "replace")
    except Exception:
        return ""


def probe(loader, part, do_write, block_sectors):
    log("programmer : %s" % loader)
    log("目标分区   : %s" % part)
    log("")

    if not os.path.isfile(loader):
        log("[X] programmer 不存在：%s" % loader)
        return 1

    if not edlman._has_edl_device():
        log("设备不在 9008，尝试 adb reboot edl ...")
        edlman.reboot_to_edl(log=log)
        time.sleep(1)

    sess = edllink.Session(loader=loader)
    rc = 1
    try:
        sess.open(timeout=90)
        fh = sess.fh.firehose
        cfg = fh.cfg
        ss = int(cfg.SECTOR_SIZE_IN_BYTES) or 512
        sess._drop_bogus_vendor()

        log("=== 会话 ===")
        log("  MemoryName        %s" % cfg.MemoryName)
        log("  SECTOR_SIZE       %d" % ss)
        log("  MaxPayload        %d" % cfg.MaxPayloadSizeToTargetInBytes)
        log("  TargetName        %s" % getattr(cfg, "TargetName", "?"))
        sh = getattr(sess.fh, "sahara", None)
        if sh is not None:
            log("  msm_id            0x%08x" % (sh.msm_id or 0))
            log("  hwidstr           %s" % getattr(sh, "hwidstr", "?"))

        buf = []
        sess.printgpt(on_line=buf.append, timeout=90)
        gpt = edllink.parse_gpt("\n".join(buf))
        if part not in gpt:
            log("[X] GPT 里没有 %s（共 %d 项）" % (part, len(gpt)))
            return 1
        e = gpt[part]
        sector = e["offset"] // ss
        log("")
        log("=== 分区 ===")
        log("  %s: 扇区 %d (0x%X)，%d 字节" % (part, sector, e["offset"], e["length"]))

        # ---- 读通路 ----
        log("")
        log("=== 读 ===")
        t0 = time.time()
        base = bytes(fh.cmd_read_buffer(0, sector, block_sectors, False).data)
        dt = time.time() - t0
        want = block_sectors * ss
        if len(base) != want:
            log("[X] 读长度不对：%d != %d" % (len(base), want))
            return 1
        log("  %d 字节，%.3fs，%.2f MB/s" % (len(base), dt, len(base) / 1048576.0 / max(dt, 1e-3)))
        log("  sha256 %s" % hashlib.sha256(base).hexdigest()[:24])

        # ---- 写通路探测：只发 program，不发数据 ----
        log("")
        log("=== 写通路探测（只发 program，不送数据）===")
        xml = ('<?xml version="1.0" ?><data>\n'
               '<program SECTOR_SIZE_IN_BYTES="%d" num_partition_sectors="%d" '
               'physical_partition_number="0" start_sector="%d" />\n</data>'
               % (ss, block_sectors, sector))
        t0 = time.time()
        rsp = fh.xmlsend(xml, False)
        dt = time.time() - t0
        body = as_text(rsp)
        for ln in body.replace("</data>", "</data>\n").splitlines():
            s = ln.strip()
            if "log value" in s or "response value" in s:
                log("  " + s[:200])
        rawmode = 'rawmode="true"' in body
        log("  响应耗时 %.2fs" % dt)
        log("  rawmode=true ? %s" % rawmode)

        if not rawmode:
            log("")
            log("[结论] 只能读，不能写。")
            log("  program 被拒绝，rawmode=false，设备不会接收数据。")
            log("  调块大小 / 调 ZLP 都没用，需要与设备匹配的 programmer。")
            rc = 2
            return rc

        log("")
        log("[结论] program 被接受，rawmode=true —— 这颗 programmer 能写。")

        if not do_write:
            log("  （未加 --write，不发数据；设备会停在 raw 接收态，reset 后释放）")
            rc = 0
            return rc

        # ---- 真写：把读到的原内容写回去 ----
        log("")
        log("=== 幂等写入 %d 字节 ===" % len(base))
        t0 = time.time()
        fh.cdc.write(base)
        fh.cdc.write(b'')
        wd = fh.wait_for_data()
        dt = time.time() - t0
        log("  写入 %.2fs，%.2f MB/s" % (dt, len(base) / 1048576.0 / max(dt, 1e-3)))
        ack = b'value="ACK"' in bytes(wd)
        log("  最终 ACK ? %s" % ack)
        if not ack:
            log("  原始回复: %r" % wd.decode("utf-8", "replace")[:400])
            rc = 2
            return rc

        rb = bytes(fh.cmd_read_buffer(0, sector, block_sectors, False).data)
        same = (rb == base)
        log("  读回逐字节一致 ? %s" % same)
        if not same:
            diff = next((i for i in range(min(len(rb), len(base))) if rb[i] != base[i]), -1)
            log("  首个差异偏移 %d (0x%X)" % (diff, diff))
            rc = 2
        else:
            rc = 0
        return rc

    finally:
        try:
            sess.reset()
            log("")
            log("reset 完成，设备退出 9008")
        except Exception as ex:
            log("reset 失败：%s —— 长按电源 15 秒" % ex)
        try:
            sess.close()
        except Exception:
            pass


def main():
    ap = argparse.ArgumentParser(description="EDL 写通路探测（判断 programmer 能否写）")
    ap.add_argument("--loader", default=None, help="Firehose programmer 路径，默认用 edlman.find_loader()")
    ap.add_argument("--part", default="misc", help="探测用分区，默认 misc（写坏也不影响开机）")
    ap.add_argument("--write", action="store_true", help="真写入读到的原内容并读回比对（幂等）")
    ap.add_argument("--sectors", type=int, default=8, help="探测数据量（扇区），默认 8 = 4KB")
    a = ap.parse_args()

    loader = a.loader or edlman.find_loader()
    try:
        return probe(loader, a.part, a.write, a.sectors)
    except SystemExit:
        raise
    except BaseException as ex:
        log("[X] %s: %s" % (type(ex).__name__, ex))
        return 1


if __name__ == "__main__":
    sys.exit(main())
