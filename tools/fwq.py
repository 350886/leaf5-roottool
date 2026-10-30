#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
fwq.py — 查 ONYX BOOX 官方固件包地址。

设备上的「系统更新」调的就是这个接口，所以查到的就是设备自己会下的那一份。
不需要设备在线、不需要 root、不需要解密工具。

用法：
    python fwq.py Leaf5
    python fwq.py Leaf5 --lang en_US
    python fwq.py Leaf5 --json          # 原始返回
    python fwq.py --list                # 内置常见型号

依赖：仅标准库。
"""

import argparse
import json
import sys
import urllib.parse
import urllib.request

API = "http://data.boox.com/api/1/firmware/update"
UA = "okhttp/3.12.0"          # 设备 updater 自己用的 UA，换成别的也能通

# 常见型号。查不到就换 lang 或问设备要 ro.product.model
KNOWN = ["Leaf", "Leaf2", "Leaf3", "Leaf3C", "Leaf5", "Leaf5C",
         "Poke5", "Poke6", "Poke7", "Nova5", "NoteX5", "NoteX6",
         "Tab10", "Tab10C", "TabUltraC", "Palma", "Palma2", "Palma2Pro",
         "GoColor7", "Go6"]


def query(model, lang="zh_CN", build=0, build_type="user", fingerprint=""):
    """
    返回 (dict|None, 原因)。

    build=0 表示"不报当前版本"，服务端会给最新全量包；
    报上 buildNumber 时可能只给增量包 —— 要全量就留 0。
    """
    where = {
        "buildNumber": build,
        "buildType": build_type,
        "deviceMAC": "",
        "lang": lang,
        "model": model,
        "submodel": "",
        "fingerprint": fingerprint,
    }
    url = API + "?where=" + urllib.parse.quote(
        json.dumps(where, separators=(",", ":")), safe="")
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            # 204 = 这个 model 没有记录；200 才有 body
            if resp.status != 200:
                return None, f"HTTP {resp.status}（该型号无记录）"
            raw = resp.read()
    except Exception as e:
        return None, f"请求失败：{e}"
    if not raw:
        return None, "空响应（该型号无记录）"
    try:
        return json.loads(raw.decode("utf-8")), ""
    except ValueError as e:
        return None, f"返回不是 JSON：{e}"


def show(d):
    urls = d.get("downloadUrlList") or []
    size = d.get("size") or 0
    print(f"  型号      {d.get('model')}  {d.get('brand')}")
    print(f"  版本      {d.get('buildDisplayId')}")
    print(f"  构建号    {d.get('buildNumber')}   {d.get('fwType')}")
    print(f"  指纹      {d.get('fingerprint')}")
    print(f"  大小      {size:,} 字节  ({size / 1024 ** 3:.2f} GiB)")
    print(f"  md5       {d.get('md5')}")
    for i, u in enumerate(urls):
        print(f"  直链[{i}]   {u}")
    if not urls:
        print("  直链      无（返回里没给 downloadUrlList）")
    notes = []
    if d.get("lockBootloader"):
        notes.append("lockBootloader=1（刷完会锁 bootloader）")
    if d.get("wipeData"):
        notes.append("wipeData=1（刷完清数据）")
    if d.get("force"):
        notes.append("force=1（强制推送）")
    if notes:
        print("  注意      " + "；".join(notes))
    cl = (d.get("changeList") or [""])[0]
    if cl:
        print("  更新说明  " + cl.replace("\n", " ")[:160])


def main():
    ap = argparse.ArgumentParser(description="查 ONYX BOOX 官方固件地址")
    ap.add_argument("model", nargs="?", help="设备型号，如 Leaf5 / NoteX5")
    ap.add_argument("--lang", default="zh_CN", help="zh_CN / en_US …（影响推送批次）")
    ap.add_argument("--build", type=int, default=0, help="当前 buildNumber，0=要最新")
    ap.add_argument("--fingerprint", default="", help="可选，精度更高")
    ap.add_argument("--json", action="store_true", help="打原始 JSON")
    ap.add_argument("--list", action="store_true", help="列常见型号")
    a = ap.parse_args()

    if a.list or not a.model:
        print("常见型号：" + "  ".join(KNOWN))
        return 0

    d, err = query(a.model, a.lang, a.build, fingerprint=a.fingerprint)
    if not d:
        print(f"[-] {a.model}：{err}")
        # 型号名不对是最常见原因 —— Leaf5 在服务端就是 Leaf5，
        # 但设备上 ro.product.model 可能报 TabBoox，那是另一套字段
        print("    换 --lang en_US 再试，或用 --list 对型号名")
        return 1

    if a.json:
        print(json.dumps(d, ensure_ascii=False, indent=2))
    else:
        show(d)
    return 0


if __name__ == "__main__":
    sys.exit(main())
