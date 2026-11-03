"""使用说明的内容（纯数据，不 import tkinter，也不 import roottool）。

分开放的两个理由：

  * `_test_dump/test_help.py` 要在不 import roottool（那会顺带加载 adb / edl /
    tkinter 一整串）的前提下检查「界面上每个按钮都有对应章节」；
  * 改文案不该碰界面代码。

行首标记（`helpwin.render()` 认这几种，加新标记要同步改那边）：

    "## "   小标题（蓝，段前留白）
    "- "    无序项（带点，悬挂缩进）
    "· "    无点缩进行（枚举、伪表格用）
    "! "    警告（黄）
    "> "    提示（灰）
    "|"     命令（等宽）
    其它    正文段落
"""

from __future__ import annotations

TITLE = "使用说明"

SECTIONS: list[tuple[str, str]] = [
    ("第一次用", """\
## 三步
- 1) 插线，手机上点「允许 USB 调试」，等顶部设备下拉框出现机型。
- 2) 点「检测」，看状态行。型号或内核对不上会被**拦在动设备之前** ——
  载荷里 62 个符号偏移是硬编码的，换一版内核去跑就是 kernel panic。
- 3) 点「一键全自动」。它会自己走完检测、部署、跑链、装 Magisk、重启、校验。

## 适用机型
只对 ONYX BOOX Leaf5 / 固件 `4.2.3-rel_0928_656b72278` / 内核
`4.19.157-perf-g77c132eccfab-dirty` #38 成立。换过固件的机器请先用
「内核适配向导」重新生成载荷，或者先用「取原厂 boot」拿到底片再适配。

> 三台 Tab（Tab8 / Tab8C / Tab10）没有对应的 EXE。它们的结论在 README 的
> 「四款机型固件实测」一节：BENGAL programmer 不对板。

## 窗口装不下的时候
窗口是 900×760，屏幕不够时自动收（最小 620）。设备行、状态行、四组选项加起来
724px，一定装不下 —— 所以上半截是滚动的，**进度条、日志、底栏固定在下半截**。

- 右边那条 8px 的细线就是滚动条，拖动它、点空白处、或者把鼠标放在上半截滚轮。
- 滚轮只在鼠标落在上半截时才滚。放在日志区上滚的是日志，两处不会一起动。
- 内容装得下时滚动条只画一条暗轨道、不画滑块 —— 看不到滑块就是真的没有更多了。
"""),

    ("一键全自动", """\
## 它做了什么
不是「把七个按钮串起来」，是每一步都用设备自己的数据自证：

- 等设备 —— `adb devices` 报 `state=device`
- 采指纹 —— 读 `/proc/kallsyms` 的符号名序列，算 digest
- 匹配载荷 —— 本地 `targets/*/manifest.json` 里 `sym_digest` 完全相等才用
- 取镜像 —— 读当前槽的 `boot` 分区，必须切得出 kernel 段
- 校验镜像 —— 镜像里的 `linux_banner` 的 commit 必须等于设备的 `/proc/version`
- 生成 target.h —— 62 个符号偏移 + 4 个手工宏全部有值才继续
- 编译 —— NDK 的 aarch64 clang 出来的 so，md5 要与设备上一致

中间只在四种情况下停：设备没连、机型或内核对不上（一个字节都不写）、
适配拿到的东西自证不上、用户点「停止」。

## 为什么要校验镜像 commit
A/B 双分区的机器上 `boot_b` 经常还是上一个固件的版本，而设备正跑 `boot_a`。
两份镜像 banner 里的 `#38` 只是本地 `make` 计数，看着一样，git commit 却不同 ——
偏移差几百字节，拿去跑就是内核在随机位置崩。工具只认 commit。

## 大概多久
- 本地已有同构建载荷：2 秒
- 用内置载荷：一两分钟
- 要走完整适配（含 EDL 往返和编译）：3~8 分钟
"""),

    ("检测 / 部署 / 开始 Root / 停止", """\
## 检测
只读。取型号、内核、root 状态，不改设备。先摸清状态再决定动哪一步时用它。

## 部署载荷
把 `preload.so` 与 `device_root.sh` 推到 `/data/local/tmp`。
「开始 Root」报缺文件时单独点这个，不必重跑整条链。

## 开始 Root
按「轮数」跑 exploit（默认 3 轮）。单轮约 96 秒、成功率约 2/3，三轮累计约 96%。
已经部署过、只想单独重跑时用它。

## 停止
中断当前任务。注意：exploit 跑在内核里，停止只是不再发新指令，
已经进内核的那一轮会自己跑完（约 96 秒）。
"""),

    ("选项怎么调", """\
## 轮数
最多抽几次 cred。勾了「要求 CAP_SYS_ADMIN」时调高 —— 该位由 KASLR 抽签决定，
约一半概率，多抽几次才稳。

## 自动适配内核（默认开）
失败后用镜像重算偏移再编 `preload.so`。换过固件的机器开着；同一台机器反复 root
可以关掉，省掉几分钟编译。

## 要求 CAP_SYS_ADMIN
只收带 mount 能力的 root。要改只读分区才勾 —— **乱勾会误判失败**：日志里读不到
`bnd=` 就直接判这一轮失败，不放行。

## adb 端口
默认 5053。无线调试换了端口才改。改完点「刷新设备」重新连。

## 跳过型号核对
型号/内核对不上也照跑。只有「确认是同一颗内核、只是版本字符串不同」时才勾，
偏移自己负责。
"""),

    ("安装 Magisk 与 AMS 修复模块", """\
## 安装 Magisk（勾了会重启一次）
exploit 拿到 root 之后热装：

- 1 `dd` 备份 `boot{slot}`，**再拉到 PC**，双向校验 md5。拉不回来就中止 ——
  只在设备上留一份不算备份，boot 写坏后系统起不来，`/data` 也读不到。
- 2 从内嵌 APK 里取 `magiskboot` / `magiskinit` / `magisk64` 推到设备
- 3 在**设备上**跑 `boot_patch.sh`（PC 跑不了：那些是 aarch64 ELF）
- 4 拉回 `new-boot.img`，**比对 kernel 段**：正常只该 ramdisk 涨几十 KB，
  kernel 必须一字节不变。变了就中止（分区未改动）
- 5 `dd` 写回 boot 分区，回读 md5
- 6 补 `/data/adb/magisk` 运行时，`adb install` Magisk App
- 7 重启，root 从此由 `magiskd` 提供

## 装 AMS 修复模块
ONYX 4.2.3 把 `ActivityManagerService.addPackageDependency` 的 `proc == null`
分支改成了自己的追踪代码，进去就解引用 null。Magisk 由 `app_process` 起、
不在 PidMap 里 ⇒ 恒 null ⇒ **Magisk App 每次启动卡在启动图**（root 本身是好的）。

补丁是单字节：`classes.dex 0x2b2fee : 38 01 33 00 → 38 01 3F 00`。
原字节不符时**直接拒绝**，不会瞎改 —— 换固件要重算偏移。

> 装了 Magisk 会自动勾上模块（结果上等价）。想分开做时先取消勾选。
"""),

    ("刷 boot 的三条通路", """\
## 为什么不能只用 fastboot
ONYX 的 abl 把 `fastboot flash` 这条 handler 裁了 —— bootloader 模式下
`fastboot flash boot_b x.img` 一律回 `remote: 'unknown command'`，四台机器实测一致。

## 三条路，按代价排
- `dd`（在 Magisk 流程里）—— 有 root 才能走；不重启，写完回读 md5
- `fastbootd 刷 boot` —— 不需要 root；10~30 秒，屏幕有提示
- `EDL 刷 boot` —— 兜底；设备黑屏进 9008，3~6 分钟

## fastbootd 为什么成立
`fastboot reboot fastboot` 是**另一条 handler**，裁 flash 不连带裁它。它拉起的是
跑在 Android 里的 userspace 守护进程，写入走 `OpenPartition → write(blockdev)`，
**完全不经过 abl 的命令分发表**。判据只认 `fastboot getvar is-userspace` 回 `yes`
（bootloader 模式回 `no`；product 名两边会重样，不能拿来判）。

## fastbootd 刷 boot 的顺序
- 1 本地验 `ANDROID!` 头
- 2 按 `ro.boot.slot_suffix` 定分区（Leaf5 是 A/B，落到 `boot_b`）
- 3 `fastboot reboot fastboot`，等 `is-userspace: yes`
- 4 比 `partition-size`，装不下就停
- 5 写
- 6 失败 → 刷回进 fastbootd 之前备份的那份，再重启
- 7 成功 → 重启回 Android

## EDL 刷 boot 的顺序
- 1 分区必须在 GPT 里，容量装得下镜像
- 2 先读一份原分区到 PC（长度必须等于 GPT 记的 length）
- 3 写
- 4 读回镜像长度那一段，sha256 与源文件逐字节比对
- 5 不符 → 用备份写回，报「已回滚」
- 6 reset 离开下载模式

> programmer 必须与 SoC 匹配：Leaf5 是 LITO，`lito_op_n10_fhprg.bin` 已内置；
> Tab 三台是 BENGAL，仓库里没有对应的 programmer，那条路在它们上走不通。
"""),

    ("取原厂 boot", """\
## 解决什么
刷 boot 得先有镜像。自己 `dd` 备份的前提是设备已经 root；官方 OTA 里带着完整
boot，纯本地解包就能取出来。

## 怎么用
点「取原厂 boot」→ 选 ONYX 官网那个整包 `update.zip`（1.74 GiB）→
工具从 `payload.bin` 抽出 `boot` 或 `init_boot`，写到
`%LOCALAPPDATA%\\Leaf5RootTool\\backup\\boot_stock.img`。
**不需要设备、不需要 root。**

## 四个要点
- **`init_boot` 优先**。Android 13 起 ramdisk 搬到 `init_boot`，两个都在时必须打
  `init_boot`；打 `boot` 会得到没有 ramdisk 的镜像，刷上去不进系统。
- **`.upx` 不能直接喂**。那是 ONYX 自己的加密容器（随机字节开头、无魔数），
  先解成 `update.zip`。
- **不整个解压**。`payload.bin` 在 zip 里是 STORED，按 local header 算绝对偏移切片读。
- 增量操作（`MOVE` / `BSDIFF` / `SOURCE_COPY` / `PUFFDIFF` / `ZUCCHINI`）遇到就报错 ——
  full OTA 里出现说明包不对。

## 别拿 dd 出来的当原厂
`--edl dump` 或内部 dump 出来的 `boot_b` 是**这台机器当前正在跑的那份**。
已经 root 过的机器，那份是 Magisk 补丁过的，拿来当「恢复原厂」的基底会把版本
固定在这一版，拿来当「重装 Magisk 的原料」也不对（要在未 patch 的 boot 上打补丁）。
"""),

    ("Google Play", """\
## 只有集成版有「装 Google Play」
普通版没有内置商店 APK，这一行不画（操作区少一行，窗口高度不变）。

## 前置条件
先在设备设置里登录 Google 账号并通过验证。ONYX 在 framework 层按 MMKV 的
`gms_enable` 拦 `com.android.vending`，那个值只在账号验证通过时由系统自己写 ——
不登录就永远停在「被拦」，`am start` 的输出里看不到这条异常（在 system_server 侧）。

## 判定
「装上了」不算数，判据是拉起之后等几秒，再看前台 Activity 是不是它。
四种出口：`launched` / `need_login` / `blocked` / `failed`。
`need_login` 会自己打开「添加 Google 账号」页面。
"""),

    ("内核适配向导", """\
## 什么时候要
OTA 升级、换 ROM、换内核之后。62 个符号偏移和 `services.jar` 的补丁点全是硬编码的。

## 符号从哪来
- **设备已 root**：向导第 1 步点「从设备读符号」，`su` 进设备读 `/proc/kallsyms`，
  不需要固件包。
- **设备没 root**：喂一份 `boot.img`（可以用「取原厂 boot」抽），向导会切 kernel 段、
  解压、反解 kallsyms，再调 NDK 现编。

## 产物在哪
`targets\\<id>\\preload.so`，在 EXE 包外 —— **不用重新打包 EXE**，下次启动自动捡。

> 首次编译要下 NDK（几百 MB），只下这一次。反解推不出的宏会逐个列出来，
> 不猜值。
"""),

    ("日志、备份与回滚", """\
## 日志
- 界面下方就是日志，不脱敏之外的都原样显示。
- 落盘：`%LOCALAPPDATA%\\Leaf5RootTool\\logs\\`。菜单「文件 → 打开日志目录」直达。

## 备份在哪
- `%LOCALAPPDATA%\\Leaf5RootTool\\backup\\` —— Magisk 流程与「取原厂 boot」的留档。
- `<工具目录>\\work\\` —— EDL 写分区前的原分区备份与读回校验副本。
  两个都留：只留一个的话，出问题时分不清「写错了」还是「读错了」。

## 怎么回滚
- 有 root：`adb push` 备份到 `/sdcard/`，再 `dd` 写回分区。
- 没 root：同一份文件走 EDL（菜单「EDL 刷 boot」或 `--edl w boot_b 文件 --yes`）。

## 三条容易踩的坑
- **写的是 `boot_b` 不是 `boot_a`**：工具按 `ro.boot.slot_suffix` 走当前槽。
  两槽系统版本不一致时，patch 出来的 boot 只对当前跑着的槽有效。
- **`boot_b.img` 不是原厂备份**：见「取原厂 boot」最后一节。
- **bootloader 必须已解锁**：`ro.boot.verifiedbootstate` 期望 `orange`，
  `ro.boot.flash.locked` 期望 `0`。锁着的机器强行刷 vbmeta 会直接开不了机。
"""),

    ("命令行", """\
不想开界面时（排障、批处理）一条命令等价：

- `--auto` —— 全自动到临时 root
- `--auto --magisk` —— 全自动到持久 root（含 Magisk）
- `--auto --magisk --no-edl` —— 同上，但禁止进 9008
- `--check` —— 只检测，不动设备
- `--root 3` —— 只跑 3 轮，不做自动适配
- `--root 5 --sysadmin` —— 要求 CAP_SYS_ADMIN
- `--root 3 --module` —— 只装 AMS 修复模块
- `--payload update.zip` —— 从官方 OTA 抽原厂 boot（不需要设备）
- `--edl w boot_b x.img` —— 只打印计划；加 `--yes` 真写
- `--force-model` —— 型号/内核不匹配也继续（偏移自己负责）
- `--port 5053` —— 指定 adb server 端口

CLI 输出同时写一份 UTF-8 日志到 `%LOCALAPPDATA%\\Leaf5RootTool\\logs\\cli_*.log`
（终端编码不是 UTF-8 时看这个）。

> `--auto` 中间不会问你任何问题。只在设备没连、机型/内核对不上、镜像自证不上、
> 编译失败这四种情况下退出并打印原因。
"""),

    ("快捷键", """\
- `F1` —— 打开本说明
- `Ctrl+F` —— 在说明里搜索（回车下一处，Shift+回车上一处）
- `Esc` —— 关闭说明窗口
- `Ctrl+L` —— 清空日志窗口（只清界面，盘上的日志不动）
- `Ctrl+Q` —— 退出
- `Ctrl+D` —— 检测设备（只读）
> 按钮自身的键盘操作照 tkinter 默认：Tab 切换焦点，空格或回车触发。
"""),
]


def sections() -> list[tuple[str, str]]:
    return SECTIONS


def plain() -> str:
    """整份说明的纯文本（导出 / 测试用）。"""
    out = [TITLE, "=" * 40, ""]
    for name, body in SECTIONS:
        out.append(name)
        out.append("-" * 40)
        out.append(body.rstrip())
        out.append("")
    return "\n".join(out)


def search(word: str) -> list[tuple[int, int]]:
    """在全部章节里找 `word`（不分大小写）。

    返回 [(章节下标, 行号)]，行号相对该章节正文起点 —— 界面要拿它算 Text 的
    绝对字符位置，给全文行号反而不对（每节是单独渲染的）。
    """
    w = (word or "").strip().lower()
    if not w:
        return []
    hits: list[tuple[int, int]] = []
    for i, (_name, body) in enumerate(SECTIONS):
        for n, line in enumerate(body.splitlines()):
            if w in line.lower():
                hits.append((i, n))
    return hits
