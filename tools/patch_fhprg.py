#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
给 lito_op_n10_fhprg.bin 打补丁：让 program 命令在 "Device verified failed"
之后不再跳去报错，而是直接进入真正的写入路径 (0x1482dac0)。

背景（反汇编结论）：
  0x1482d960  b.eq  0x1482d9a0   ; 当 [G+0x10]==1 && [G+0x14]==1 才走 "Bypass checking"
  0x1482d968  cbz   w9, 0x1482d9b4 ; [G+0x18]==0 时走 token 路径
  0x1482d96c..0x1482d970  X1 = "Device verified failed"
  0x1482d974  b     0x1482da20   ; -> 报错，rawmode=false
  0x1482dac0  ...                ; 真正调用写入例程，读 sp+0x38/0x3c/0x40

G 的初始化在 0x1483587c：
  str w8, [x19]        ; G+0x00 = 5
  str xzr, [x19, 8]    ; G+0x08 = 0
  str w9, [x19, 0x18]  ; G+0x18 = 1   <- 硬写死为 1
G+0x10 / G+0x14 (ato/fm) 全程序无赋值，.bss 恒 0
=> fm==1 && ato==1 永不成立，Bypass 分支是死代码

补丁：把 0x1482d974 的 b 0x1482da20 改成 b 0x1482dac0
  原字节 2b 00 00 14  (0x1400002b, 目标 0x1482da20)
  新字节 53 00 00 14  (0x14000053, 目标 0x1482dac0)
sp+0x38/0x3c/0x40 由 0x1482d934 的 bl 0x1482d49c 填好，跳过去不会读到未初始化栈。

用法:
  python patch_fhprg.py <原始programmer> <输出programmer>
"""
import sys

VA_TO_OFF = 0x14817000 - 0x3000      # LOAD0: va 0x14817000 对应文件偏移 0x3000

PATCHES = [
    # (虚拟地址, 原字节, 新字节, 说明)
    (0x1482D974, bytes.fromhex("2b000014"), bytes.fromhex("53000014"),
     "b 0x1482da20 (报错) -> b 0x1482dac0 (直接写入)"),
]

def main():
    if len(sys.argv) < 3:
        print(__doc__)
        sys.exit(1)
    src, dst = sys.argv[1], sys.argv[2]
    data = bytearray(open(src, "rb").read())
    print("源文件: %s  (%d 字节)" % (src, len(data)))

    ok = True
    for va, old, new, desc in PATCHES:
        off = va - VA_TO_OFF
        cur = bytes(data[off:off + len(old)])
        print("\n[%#x] 文件偏移 %#x  %s" % (va, off, desc))
        print("  当前字节: %s" % cur.hex(" "))
        if cur != old:
            print("  [!] 与预期不符（期望 %s），跳过" % old.hex(" "))
            ok = False
            continue
        data[off:off + len(new)] = new
        print("  已写入  : %s" % new.hex(" "))

    if not ok:
        print("\n有补丁未应用，未输出文件。")
        sys.exit(2)

    open(dst, "wb").write(data)
    print("\n输出: %s  (%d 字节)" % (dst, len(data)))
    print("校验: 除这 %d 字节外，文件其余部分与原始一致。" %
          sum(len(p[2]) for p in PATCHES))

if __name__ == "__main__":
    main()
