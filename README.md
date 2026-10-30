# Leaf5 Root Tool

ONYX BOOX Leaf5 的一键 root 客户端。内嵌 adb，不依赖机器上装没装 [platform-tools](https://developer.android.com/tools/releases/platform-tools)。

> **只对一台机器成立**：ONYX BOOX Leaf5 / 固件 `4.2.3-rel_0928_656b72278` /
> 内核 `4.19.157-perf-g77c132eccfab-dirty` #38。
> 型号或内核对不上会被**拦在动设备之前** —— 载荷里 62 个符号偏移和
> `services.jar` 的补丁点全是硬编码的，换一版内核就是 kernel panic。
> 换了固件的机器请先用「内核适配向导」重新生成载荷。

漏洞链本身（C 源码、偏移推导、手工命令行流程）在 **[350886/leaf5-ghostlock](https://github.com/350886/leaf5-ghostlock)**；
本仓库是它的 Windows 封装 —— 加上 adb、EDL、载荷适配和 Magisk 安装。

双击 `Leaf5RootTool.exe`，点「一键全自动」。剩下的它自己走：

```
等设备 → 检测 → 匹配本地载荷 → 部署 → 跑链（最多 N 轮）
        └─ 全没成 → 读设备当前 boot 分区 → 反解符号 → 反汇编推手工宏
                    → 编译 preload.so → 换载荷再跑
        └─ 成了 → 装 Magisk → 重启 → 校验
```

中间只在四种情况下停：设备不在线（等人插线/点授权）、**机型或内核对不上**
（一个字节都不往设备写）、适配拿到的东西自证不上（宁可停也不拿错偏移去崩内核）、
用户点停止。

---

## 前置条件

| 项 | 要求 |
|----|------|
| 设备 | ONYX BOOX Leaf5（`ro.product.model=Leaf5`） |
| 系统 | Android 13 / ONYX 固件 `4.2.3-rel_0928_656b72278` |
| 内核 | `4.19.157-perf-g77c132eccfab-dirty` #38（`uname -r` 核对） |
| 分区 | A/B，当前活动槽是 `_b`（`boot_b`） |
| 引导状态 | `ro.boot.verifiedbootstate=orange`、`ro.boot.flash.locked=0`（已解锁） |
| 数据线 | USB 连接，已在「开发者选项」里打开 **USB 调试** |
| 授权 | 第一次连会在屏幕上弹「允许 USB 调试」，点允许 |

**别的机型、别的内核能不能用** → 见下面「[能 root 哪些设备](#能-root-哪些设备)」。
同一次内核构建出来的机器，载荷是通用的。

### 型号或内核对不上会直接停下

`1.1.3` 起是硬拦，不是警告。检测阶段读 `ro.product.model` 和 `uname -r`，
任何一个不匹配就停在「跑链」之前，一个字节都不往设备写。

```
============================================================
  已停止：这台机器不是本工具适配的机型
============================================================
    · 型号是 Tab10，不是 Leaf5 —— 载荷里 62 个偏移只对这一型成立
  本工具只对 Leaf5 / 固件 4.2.3-rel_0928 / 内核 4.19.157 生成过偏移。
  继续往下会做：推载荷 → 跑内核 exploit → （勾了 Magisk）写 boot 分区。
  偏移不对的后果是 kernel panic，严重时要 9008 刷回。
============================================================
```

要强行跳过（比如你自己算过新偏移）：

- 命令行：`Leaf5RootTool.exe --auto --force-model`
- 界面：勾「跳过型号核对（偏移不对会 panic）」再点一键

只想看看这台机器是什么（不跑任何 exploit）：`Leaf5RootTool.exe --check`，
这条路不做机型判定。

**为什么拦得这么死** —— 主流程接下来的动作是：把 `preload.so` 推进
`/data/local/tmp`、以 `LD_PRELOAD` 起 exploit 改 `task_struct->cred`、
（勾了 Magisk）读 `boot_b`、打 Magisk patch、`dd` 写回分区。这四步里
前两步偏移错了是 kernel panic，第三步错了是写坏 boot，第四步错了是开不了机。
都不是"再点一次就好"的量级。

### 设备已经 root 过：也会先停下

`1.1.3` 起，点一键之前先查一次设备上有没有能用的 `su`（`roottool.py:687`
`precheck_root()`）。有就不推载荷、不跑 exploit，把结论当**绿色提示**给出
（不是红色失败 —— 一个字节都没写设备）。

```
  设备已经是 Magisk root（31.1:MAGISK:R，/debug_ramdisk/su），重启后依然有效，
  没有必要再跑一遍。
```

拦不拦看**两件事**：root 是哪种来路，以及你勾了什么。

| 设备上的 root | 勾选 | 行为 |
|---|---|---|
| Magisk（`/debug_ramdisk/su`），重启仍在 | 什么都没勾 | **停**，提示已经是 root |
| Magisk | 勾「安装 Magisk」 | **停** —— 会拿已 patch 的 boot 再 patch 一次，叠补丁有写坏风险 |
| Magisk | 只勾「安装 AMS 模块」 | 放行，**跳过 exploit**，直接装模块 |
| exploit 临时 root（`DEV_SU`），重启就没了 | 什么都没勾 | **停**，并说明要持久化就勾 Magisk |
| exploit 临时 root | 勾「安装 Magisk」 | 放行，**跳过 exploit**，用现有 su 直接装 |
| 任意 | 显式「强制重跑」 | 全放行，日志打 `[!] 已要求强制重跑` |

两条来路区别对待的原因：`/debug_ramdisk/su` 是 Magisk 给的，重启后还在，再跑一遍
纯属多余；`DEV_SU` 是 exploit 自建的，只对本次开机有效 —— 这时跳过 exploit、
接着装 Magisk 是有意义的一步，不是重复劳动。

为什么值得单独拦一道：exploit 干的是 patch 内核结构体（`rt_mutex_waiter` 那套），
拿到的是**同一种 root**。已经有 root 再 patch 一遍没有任何收益，代价是两轮内核态
竞态，其中一轮挂住就是 `device offline`。

要跳过（换 Magisk 版本、重打 boot、自己排查问题）：

- 界面：提示框上点「是」，只对这一轮有效，下一轮自动复位
- 命令行：`Leaf5RootTool.exe --auto --force-rerun`

换 Magisk 版本或重打 boot，用 Magisk App 里的「安装 → 直接安装」更稳 —— 它清楚
自己上次写了什么，本工具不知道。

---

## 能 root 哪些设备

「前置条件」那张表是**开箱即用**的范围 —— 一个字节不改、点一下就成的只有那一台。
它不是"全部能跑"的范围。

载荷选哪一份，判据是**内核符号序列**，不是机型（`adapter.py` 的 `pick_payload()`）：

```
① 符号名序列哈希一致   → 同一次内核构建，直接拿来用（最可信）
② 设备指纹一致
③ 内核版本串一致       → 同版本不同构建，次优
```

62 个偏移全是「符号地址 − `_text`」的差值，4 个手工常量是结构体布局与栈帧大小，
只跟内核镜像有关；`device_root.sh` 只碰 `/system/bin/sleep` 和 `/data/local/tmp`，
不读任何机型属性。**所以同一次内核构建出来的机器，载荷本身是通用的。**

### 分档

| 设备 | 内核 | 能到什么程度 | 要做什么 |
|---|---|---|---|
| Leaf5 | `4.19.157-perf-g77c132eccfab-dirty` #38 | 全部，含 Magisk 持久化 | 不用做，开箱 |
| Leaf5 | 同内核，换了固件（4.2.4 之类） | 临时 root 直接能；Magisk 大概率要重定位补丁点 | 先只跑临时 root 验证；`services.jar` 另核 |
| Leaf5 | 4.19.157 的其他 build（串里仍含 `4.19.157`） | 重编载荷后能 | 跑「内核适配向导」，手填 4 个宏 |
| Leaf5 | 4.19.200 / 5.4 / 6.1 | 向导编得出来，能不能过要实跑；5.x 起结构变了，成功率低 | 同上，门槛更高；先只跑临时 root |
| ONYX 其他机型 | **整串相同的内核** | 临时 root 能（载荷会被自动选中）；Magisk 看下面两条 | 勾「跳过型号核对」；验 `services.jar` |
| ONYX 其他机型 | 不同内核 | 要重新适配 | 向导重编 + 4 个值；SoC 变了还要换 EDL programmer |
| 非 ONYX | — | 不适用 | 链子本身是通用的，但机型常量、分区布局、sepolicy 全要重做 |

### 同内核、不同机型：只有三处会变

| 部分 | 为什么变 | 工具怎么兜 |
|---|---|---|
| `services.jar` 的 DEX 补丁点 `0x2b2fee` | 跟**系统固件**走，不跟内核走；不同机型 framework 不同 | 字节不符直接抛 `AdbError` 停下（`roottool.py:238`），不写坏。后果是 Magisk App 启动 NPE，root 本身正常 |
| boot 分区 | A-only / A/B、header 参数不同 | 只读 kernel/ramdisk size + `hdr_ver`（`roottool.py:141`）；实际 patch 由设备上的 `magiskboot` 做，不吃硬编码 page_size。槽位读 `ro.boot.slot_suffix`，读不到回退 `/proc/cmdline`（`autopilot.py:201`） |
| SELinux 策略 | 各机型 sepolicy 不同 | exploit round1 要转 permissive。**这是最可能卡住的一步** |

EDL 那条支路（只有「没 root 又要读 boot」才用）按 HW_ID 分，同内核通常同 SoC 平台，
programmer 大概率仍可用；`--edl gpt` 一跑就知道。

### 自己先判

```bash
adb shell uname -r              # 整串比对，不是"都写着 4.19.157"就行
adb shell getprop ro.product.model
Leaf5RootTool.exe --check       # 不动设备，只打读数
```

### 建议顺序（前两步都可逆）

```bash
# 1. 只跑临时 root，不勾 Magisk —— 零写入，重启就恢复
Leaf5RootTool.exe --auto --force-model

# 2. 过了再核 services.jar 补丁点（读出来看，不改）
adb shell su -c "cp /system/framework/services.jar /data/local/tmp/s.jar"
#    解压看 classes.dex 0x2b2fee 处是不是 38 01 33 00

# 3. 前两步都过，才勾 Magisk 动 boot
```

第 1 步过不了就别往下 —— 那是偏移或 sepolicy 的问题，硬上 Magisk 只会把 boot 写坏。

### 闸门能拦什么，拦不住什么

判据是 `TARGET_MODEL not in model and "TabBoox" not in model`（`roottool.py:570`）。
实测这台 Leaf5 报 `ro.product.model=Leaf5`，正常过闸；`TabBoox` 出现在的是
`ro.build.fingerprint`（`ONYX/TabBoox/TabBoox:13/...`）里，不是 model 字段。

后半个 `"TabBoox"` 条件是留给 model 真报 TabBoox 的机器的。ONYX 有几代产品共用
这个 platform 名，如果哪台的 `ro.product.model` 也返回它，就会被当成同类放行 ——
**这种机器闸门不拦**。型号名字对、内核不对的更危险：它照样往下推载荷。

所以别把闸门当授权书。先跑 `--check`，自己看 model 和 `uname -r` 两个值。

### 原厂固件包：地址、解密、提 boot

`boot_b.img` 是 Magisk patch 过的，不能当原厂基底。原厂镜像在官方 `update.upx` 里，
设备上「系统更新」点的就是这个接口：

```bash
python tools/fwq.py Leaf5
#   版本      2026-09-28_15-24_4.2.3-rel_0928_656b72278
#   构建号    9015   release
#   大小      1,867,290,835 字节  (1.74 GiB)
#   md5       af649ee4fc6c0ccbb18a07610419db77
#   直链[0]   http://firmware.boox.com/af649ee4fc6c0ccbb18a07610419db77/update.upx
```

接口是 `http://data.boox.com/api/1/firmware/update?where={...}`，字段
`buildNumber / buildType / deviceMAC / lang / model / submodel / fingerprint`。
`model` 填设备 `ro.product.model` 那个串（这台是 `Leaf5`）。`buildNumber=0`
要的是最新**全量**包；报上当前版本号可能只回增量包。

下载下来是加密的，用 [Hagb/decryptBooxUpdateUpx](https://github.com/Hagb/decryptBooxUpdateUpx) 解：

```bash
pip install pycryptodome
python DeBooxUpx.py Leaf5 update.upx update.zip
```

Leaf5 的 Key/IV 已经在它的 `BooxKeys.csv` 里（`648C3243…` / `DFA378E2…`），
不用自己抓。算法是 AES-128-CFB，整文件流式解，解出来头 4 字节就是 `PK\x03\x04`。

```bash
unzip -o update.zip payload.bin payload_properties.txt
payload-dumper-go -p boot payload.bin     # 或 cyxx/extract_android_ota_payload
```

注意：`payload.bin` 里是 `boot` 分区本体，A/B 机器刷回时按当前槽写
（`boot_a` 或 `boot_b`），别两个槽都写。

实测到哪一步：接口返回与 upx 解密这两步在本机跑过 —— 拉前 4 KB 用 Leaf5 的
Key/IV 解，头是 `PK\x03\x04`、第一个 entry 是 `META-INF/com/android/`。
`payload.bin` 提取那步没跑（1.74 GiB 全量没下），命令按工具用法写的。

---

## Google Play（和 root 无关的一条腿）

界面上第四个按钮「装 Google Play」，命令行 `--gplay`。**不需要先 root**，
root 过的机器也不需要再走一遍。这条腿不进 root 流程，`precheck_root()` 也管不着它。

### 固件里其实带了 GMS，别去下三件套

把 4.2.3 那个包的三个分区全列过一遍：

| 分区 | 路径 | |
|---|---|---|
| `product` | `priv-app/GmsCore/GmsCore.apk` 147,488,796 字节 | GMS 本体在 |
| `system_ext` | `priv-app/GoogleServicesFramework/` | GSF 在 |
| `product` | `GoogleRestore` / `ConfigUpdater` / `OneTimeInitializer` | 配套在 |
| `product` | `overlay/GmsConfigOverlayCommon` / `GmsConfigOverlayGSA` | 资源在 |
| `system` | `app/GoogleExtShared` | 共享库在 |
| 全部三个 | `Phonesky` / `com.android.vending` | **一个都没有** |

所以缺的只有 Play 商店这一个 APK。装三件套会**覆盖**掉预置的 GmsCore ——
签名不一样还会装失败，装成功了更麻烦（预置的那份被顶掉，GSF ID 全变）。别装。

### 闪退不是缺组件，是框架层拦

`framework.jar` 里 ONYX 自己加的一段：

```java
// android.onyx.optimization.Constant
DISABLED_PACKAGES = { "com.android.vending" }

// android.onyx.utils.ActivityManagerHelper
static boolean gmsEnabled() { return OnyxMMKVConfigHelper.getBool("gms_enable", false); }

// com.android.server.wm.ActivityStarter.executeRequest()
if (!gmsEnabled() && isDisallow(pkg) && !isSystemApp(pkg))
    throw new SecurityException(
        "This app is not allowed to start because Google Play is disabled.");
```

黑名单里只有商店一个包，判据是 MMKV 里的 `gms_enable`，默认 `false`。
**商店装成用户应用 → 不在 system → 被拦 → 一开就退回桌面。** 这就是"闪退"。

### 正确的开法只有一条：登录 Google 账号

`gms_enable` 由 ONYX 自己在**账号验证通过的那一刻**写入 —— 设置里那个
「启用 Google Play」开关，在 4.x 里就是这套流程的壳。走完：

```
设置 -> 账号 -> 添加账号 -> Google -> 登录 -> 完成验证
-> OTA 服务后台注册设备 -> 关机再开 -> 商店能开了
```

**工具不写这个值**，理由三条：

- MMKV 是 mmap 二进制（有文件锁 + CRC），外部改要先停 ONYX 进程，改坏就是配置全丢；
- ONYX 一升级换 key 名或换存储实现，写死的偏移立刻失效；
- 这个值的语义是"本机已验证过 Google 账号"，硬写进去等于伪造验证状态，
  Play 服务那边照样认为设备没认证。

工具做的是**把用户送到那个页面**：连不上就 `am start` 拉起
`android.settings.ADD_ACCOUNT_SETTINGS`（限定 `account_types=com.google`，失败退到不限类型，
再退到设置首页），用户在设备上登录完，ONYX 自己把开关写进去。

### 四个动作

```
probe()             pm list packages / dumpsys package / dumpsys account / 前台 Activity
install(apk)        adb install -r -d（带 -d，从 44.x 退到 42.x 才不会被版本降级拦住）
open_account_page() 三档回落拉起添加账号页
launch_store()      am start -W + 等 3 秒 + 读 topResumedActivity，两个判据都看
```

`launch_store()` 的两个判据缺一不可：`SecurityException` 抛在 system_server 侧，
不一定出现在 `am` 的输出里；而只看前台 Activity 又会把"起来了但立刻闪退"判成成功。
**两个都不对才算失败。**

`enable()` 把这些串成一条，返回固定字段的 dict（`ok` / `stage` / `detail` / `need_manual`），
`stage` 一共五种：`installed` / `launched` / `need_login` / `blocked` / `failed`。

**已经装了但拉不起来时会自动换包重试一次**（`reinstall_if_blocked=True`，UI 和 `--gplay` 都开）。
这一条是给 44.x 准备的：那个版本在 Leaf5 上装得上、一开就退，
手上有 42.x 的包就直接覆盖换上，比让人去猜"为什么有账号还是 blocked"省事。
没开这个开关就只探测不动设备。

### APK 放哪

商店包 64 MB，**不打进 EXE**（会把 37 MB 撑到 100 MB）。工具按这个顺序找，取体积最大的那个：

```
--apk 显式指定
<EXE 同级>/assets/apk/
<EXE 同级>/apk/
<cwd>/apk/
```

文件名含 `vending` 或 `Phonesky`、扩展名 `.apk` 就会被认出来。
一次找不到会直接把该放哪几个目录打在报错里，不用猜。

打包好的 `dist\apk\` 里已经放了一份 `Phonesky_42.0.18-31.apk`。
**把 EXE 挪到别的机器用时，`apk` 文件夹要一起拷过去** —— 只拷 EXE 的话，
商店没装的设备会停在"没找到商店 APK"这一步。

版本选 **Google Play Store 42.x / 44.x，SDK 31+，arm64-v8a，nodpi**。
44.6.15 在 Leaf5 上装得上但一开就退；42.0.18-31 实测能用。

### 现成的这条路走不通时

- **商店能开，但装应用提示「设备未通过 Play 保护认证」** —— 拿 GSF ID 去
  `google.com/android/uncertified` 登记，几分钟到几小时生效。
- **`stage=blocked` 且 detail 里已经有账号** —— 账号在但开关没写进去。
  去设置里把那个 Google 账号删掉重登一次，让验证流程重跑一遍。
- **`stage=failed` 且提示 GMS 不在系统里** —— 这台固件把 GMS 裁了，
  装 APK 解决不了，得换带 GMS 的固件。工具管不了这一种。

---

## 一键全自动做了什么

主按钮一条命令跑完全程。它不是"把七个按钮串起来"，是**每一步都用设备自己的
数据自证**，任何一步对不上就停在那一步：

| 步骤 | 输入 | 自证条件 | 不满足时 |
|---|---|---|---|
| 等设备 | `adb devices` | state=`device` | 等 180 秒，期间提示插线/授权 |
| 采指纹 | `/proc/kallsyms` 符号名序列 | 零地址比例能算出非空 digest | 停下（读不到就没法判断该用哪份载荷） |
| 匹配载荷 | 本地 `targets/*/manifest.json` | `sym_digest` 完全相等 | 用内置载荷，走完 N 轮再适配 |
| 取镜像 | 当前槽的 `boot` 分区 | 有 `ANDROID!` 头、能切出 kernel 段 | 没有 root 时进 9008（屏幕会黑，正常） |
| 校验镜像 | 镜像里的 `linux_banner` | commit 与设备 `/proc/version` 一致 | 换另一个槽重抓；两次都对不上就停 |
| 生成 target.h | kernel 段的 kallsyms + 反汇编 | 55 个符号偏移 + 4 个手工宏全部有值 | 停下并列出推不出的宏名 |
| 编译 | NDK 的 aarch64 clang | md5 与设备上一致 | 停下并给第一条 error |

**为什么镜像校验这一步不能省**：A/B 双分区的机器上 `boot_b` 经常是上一个固件
版本，而设备正在跑 `boot_a`。两份镜像的 build 号可能都是 `#38`（那只是本地
`make` 计数），git commit 却不同 —— 偏移差几百字节，拿去跑就是内核在随机
位置崩。工具只认 commit。

少数机器第一次就能成（本地已有同构建载荷，2 秒）；大多数机器第一次
用内置载荷就能成（模板 target.h 本来就从这台型号上取的）；换过固件的机器
会走完整适配（3~8 分钟，含 EDL 往返和编译）。

---

## 三个选项

界面上是三级递进，可以单独勾：

**1. 一键 Root（必做）**

`preload.so` 通过 GhostLock（CVE-2026-43499，rtmutex 栈 UAF）在 `/system/bin/sleep`
里跑完三轮约束写，把 uid 改成 0 并装一个 `/data/local/tmp/su`。

- 单轮约 96 秒，成功率约 2/3；默认重试 3 次，累计 ≈96%
- `need CAP_SYS_ADMIN` 勾上后，只有拿到 bit21 才收工（该位由 KASLR 抽签决定，约一半概率）
- 重启后 SELinux 回 Enforcing，临时 root 失效，要重跑

**2. 安装 Magisk（可选，勾了会自动勾第 3 项）**

exploit 拿到 root 后，热装 Magisk：

1. `dd` 备份 `boot{slot}` 到 `/data/local/tmp/mgk/stock_boot.img`，**再拉到 PC**
   （`%LOCALAPPDATA%\Leaf5RootTool\backup\stock_boot{slot}_{时间}.img`），双向校验 md5。
   拉不回来就中止 —— 只在设备上留一份不算备份，boot 写坏后系统起不来，`/data` 也读不到
2. 从内嵌 APK 里取 `magiskboot` / `magiskinit` / `magisk64` 等，推到设备
3. 在**设备上**跑 `boot_patch.sh`（PC 跑不了：那些是 aarch64 ELF）
4. 拉回 `new-boot.img`，**比对 kernel 段**：正常只能是 ramdisk 涨几十 KB，kernel 必须一字节不变。
   变了就说明补丁工具不对或分区拿错，直接中止（分区未改动）
5. `dd` 写回 boot 分区，回读 md5 校验
6. 补 `/data/adb/magisk` 运行时（缺 `busybox` 会让 `setup_magisk_env` 直接 abort，模块永不挂载）
7. `adb install` Magisk App
8. 重启，root 从此由 `magiskd` 提供，不再依赖 exploit

写回用 `dd` 而不是 fastboot：ONYX 的 abl 把 flash 命令裁了，`fastboot flash boot_b`
一律返回 `remote: 'unknown command'`。

**回滚**：任何一步失败，`backup\` 里那份原版 boot 就是退路：

```bash
# 在 PC 上，把留档推回设备再写回分区
adb push stock_boot_b_YYYYmmdd_HHMMSS.img /sdcard/
adb shell su -c 'dd if=/sdcard/stock_boot_b_YYYYmmdd_HHMMSS.img of=/dev/block/by-name/boot_b bs=1M'
```

**3. 装 AMS 修复模块（可选）**

ONYX 4.2.3 的 `ActivityManagerService.addPackageDependency` 有个空指针：

```
java.lang.NullPointerException: Attempt to read from field
'android.content.pm.ApplicationInfo com.android.server.am.ProcessRecord.info'
in ... ActivityManagerService.addPackageDependency(java.lang.String)
```

AOSP 原版是 `if (proc == null) return;`，文石把 null 分支改成跳去自己的 WebView
使用追踪代码，进去就解引用。Magisk 的 root 守护进程由 `app_process` 起、不在 PidMap
里 ⇒ `proc` 恒 null ⇒ **Magisk App 每次启动都卡在启动图**（root 本身是好的）。

修法是单字节补丁：

```
classes.dex 0x2b2fee : 38 01 33 00  →  38 01 3F 00
  0x0019 if-eqz v1, +0x33（文石分支） → +0x3F（方法里唯一的 return-void）
```

程序运行时会从设备读原版 `services.jar`、打补丁、重算 DEX 头的 SHA-1 与 Adler32，
再铺成 Magisk 模块 `/data/adb/modules/boox-ams-fix/`。

补丁点上的原字节不是 `38 01 33 00` 时**直接拒绝**，不会瞎改 —— 换固件要重算偏移。

模块在 Magisk 里长什么样、怎么验证生效、怎么停用，见下面「Magisk 里的 Leaf5 模块」。

---

## 命令行

不想开界面的时候（排障、批处理），一条命令等价：

```bash
Leaf5RootTool.exe --auto                    # 全自动到临时 root
Leaf5RootTool.exe --auto --magisk           # 全自动到持久 root（含 Magisk）
Leaf5RootTool.exe --auto --magisk --no-edl  # 同上，但禁止进 9008
Leaf5RootTool.exe --check                   # 只检测，不动设备
Leaf5RootTool.exe --root 3                  # 只跑 3 轮，不做自动适配
Leaf5RootTool.exe --auto --force-model      # 机型/内核不匹配也硬走（自己算过偏移时用）
```

`--auto` 中间不会问你任何问题。它只在设备没连、机型/内核对不上、镜像自证不上、
编译失败这四种情况下退出并打印原因。


```
Leaf5RootTool.exe                     图形界面
Leaf5RootTool.exe --check             只检测设备，不动任何东西
Leaf5RootTool.exe --root 3            无界面跑 3 轮
Leaf5RootTool.exe --root 5 --sysadmin 要求 CAP_SYS_ADMIN
Leaf5RootTool.exe --root 3 --magisk   顺带装 Magisk
Leaf5RootTool.exe --root 3 --module   只装 AMS 修复模块（Magisk 已装）
Leaf5RootTool.exe --force-model       型号/内核不匹配时仍然继续（偏移自己负责）
Leaf5RootTool.exe --port 5053         指定 adb server 端口
```

CLI 输出同时写一份 UTF-8 日志到
`%LOCALAPPDATA%\Leaf5RootTool\logs\cli_*.log`（终端编码不是 UTF-8 时看这个）。

---

## 判定成功的三条

同时成立才算：

1. `/proc/uptime` 没有回绕（回绕 = 中途 panic 重启）
2. `exec_probe.txt` 的 `CapEff` 不是 `c0` / `0`
3. `su -c id` 输出 `uid=0`

⚠ 判断 `CAP_SYS_ADMIN` 要看 route 日志里的 `bnd=`，**不要看 exec 后的 `CapEff`** ——
这个内核 `execve` 的 `pP'` 落在 inheritable 上，`CapEff` 只是 `CapInh` 的镜像。

---

## Magisk 里的 Leaf5 模块（`boox-ams-fix`）

装完 Magisk 后，Magisk App 的「模块」列表里会多出一条 **`Boox AMS NPE Fix (Leaf5 4.2.3)`**：

| 字段 | 值 |
|---|---|
| 名称 | `Boox AMS NPE Fix (Leaf5 4.2.3)` |
| ID | `boox-ams-fix` |
| 版本 | `v1.0-leaf5-4.2.3` |
| 作者 | `leaf5-roottool` |
| 落盘 | `/data/adb/modules/boox-ams-fix/` |

**它只做一件事**：把打过补丁的 `services.jar` 用 Magisk 的 magic mount 盖到
`/system/framework/services.jar` 上面。模块目录里只有两个文件：

```
/data/adb/modules/boox-ams-fix/
├── module.prop                     模块信息（上面那张表的来源）
└── system/framework/services.jar   打过补丁的那份
```

**为什么必须走模块**：`/system` 是 dm-verity 保护的 dm-linear（`/dev/block/dm-8`），
有 `CAP_SYS_ADMIN` 也 remount 不成可写。magic mount 不碰分区内容，只在挂载层叠一份 ——
随时能撤，这是它唯一比「直接改系统」强的地方。

### 不装会怎样

root 本身不受影响，`su -c id` 照样是 `uid=0`。坏的是 **Magisk App 打不开**：
一点就卡在启动图，或者闪一下退回桌面。

根因在 ONYX 的 `ActivityManagerService.addPackageDependency`：

```
AOSP : if (proc == null) return;
ONYX : if (proc == null) → 跳去自己的 WebView 使用追踪
                           → iget-object v0, v1, ProcessRecord;->info
                             v1 为 null ⇒ NPE
```

Magisk 的 root 守护进程由 `app_process` 拉起、不在 PidMap 里，`proc` 恒为 null，
所以每次启动都落进这个分支。程序装完会执行一次 `pm enable com.topjohnwu.magisk`，
那只解决 ONYX 把 App 冻结成 `enabled=3` 的问题，跟这个 NPE 是两回事。

### 怎么确认它真的生效

```bash
adb shell su -c 'cat /data/adb/modules/boox-ams-fix/module.prop'
adb shell su -c 'ls /data/adb/modules/boox-ams-fix/system/framework/'

# 重启之后，被挂载的那份应该和模块里那份逐字节一致
adb shell su -c 'md5sum /system/framework/services.jar                  /data/adb/modules/boox-ams-fix/system/framework/services.jar'
```

两个 md5 相同就是 magic mount 生效了。不同的话按这个顺序查：

- `/data/adb/modules/boox-ams-fix/` 下有没有 `disable` 文件 —— 有就是被停用了
- `/data/adb/magisk/busybox` 在不在 —— 缺了 `setup_magisk_env` 会 abort，
  `post-fs-data` 提前返回，**所有**模块都不挂载，不只这一个
- Magisk App 里显示「已移除」但目录还在，说明模块是开机后才铺的，再重启一次

### 不要了怎么退

```bash
# 停用：下次开机不再挂载，目录保留，随时能开回来
adb shell su -c 'touch /data/adb/modules/boox-ams-fix/disable'

# 彻底删除
adb shell su -c 'rm -rf /data/adb/modules/boox-ams-fix'
```

两种都要重启才生效。删掉之后 Magisk App 会重新卡在启动图 —— 那是回到原厂行为，
不是把系统搞坏了。

### 补丁点

`classes.dex` 里一个 4 字节改动（`roottool.py:107-109`）：

```
0x2b2fee : 38 01 33 00  →  38 01 3F 00
           if-eqz v1, +0x33        if-eqz v1, +0x3F（方法尾部唯一的 return-void）
```

改完必须重算 DEX 头两个校验，ART 只认这两个，漏一个就拒绝加载：

| 字段 | 偏移 | 算法 |
|---|---|---|
| `checksum` | `0x08:0x0C` | Adler32 over `[12:]` |
| `signature` | `0x0C:0x20` | SHA-1 over `[32:]` |

补丁点上的原字节不是 `38 01 33 00` 时程序直接拒绝，不会硬改 —— 换固件要重算偏移。

---

## 已知限制

- ramdisk 没带 `PREINITDEVICE`，启动日志有 `W Magisk : mount: preinit dir not found`，不影响模块挂载
- ONYX 会自动冻结 Magisk App（`enabled=3` DISABLED_USER），重启后 `am start` 报
  `Activity class does not exist`，程序在装完会执行一次 `pm enable`
- Magisk 默认策略会拒 shell 的 su 请求，第一次要在 App 的「超级用户」里把 Shell 打开
- `/system` 是 dm-verity 保护的 dm-linear，SYS_ADMIN 也 remount 不动；`/data` 是 `nosuid`，
  `chmod 4755` 永远无效

### 三条容易踩的坑（装之前先看）

**1. 写的是 `boot_b`，不是 `boot_a`**

Leaf5 是 A/B 机型，本工具读 `ro.boot.slot_suffix` 取当前活动槽再动。这台机器
出厂停在 `_b`，所以默认写 `boot_b`。如果你的机器在 `_a`（刷过别的固件、或
`fastboot --set-active=a` 来过），工具会跟着 `_b`/`_a` 走 —— 但如果两个槽的
系统版本不一致，**patch 出来的 boot 只对当前跑着的那个槽有效**，写进另一个槽
等于没生效（下次切过去依旧没 root）。

验证当前槽：

```
adb shell getprop ro.boot.slot_suffix
```

**2. `boot_b.img` 不是原厂备份，别拿它救命**

`--edl dump` 和内部 dump 出来的 `boot_b`，是**这台机器当前正在跑的那份**。
已经 root 过的机器，那份 boot 是 Magisk 31.1 patch 过的 ——
拿来当"恢复原厂"的基底会把你 Magisk 版本固定在这一版，拿来当"重装 Magisk
的原料"也不对（Magisk 要在**未 patch** 的 boot 上打补丁，叠着打会出问题）。

要原厂 boot，只能从 ONYX 官方固件包里取 `boot.img`。

**3. bootloader 必须已解锁**

```
adb shell getprop ro.boot.verifiedbootstate   # 期望 orange
adb shell getprop ro.boot.flash.locked        # 期望 0
```

读到 `green` / `1` 就是锁着的。锁着的机器 `boot` 分区写不进去，`vbmeta`
校验也过不去 —— 强行刷 `vbmeta` 会直接开不了机。这条路本工具不碰，
先自己 `fastboot flashing unlock`。

---

## 内核适配（换固件 / 换内核后重编载荷）

内置的 `preload.so` 里写死了 60 多个符号偏移，全部只对
`ONYX 4.2.3-rel_0928 / 内核 4.19.157-perf-g3d47a6619220-dirty #38` 成立。
换一版固件，这些偏移就全废了，直接跑会内核 panic。这个向导负责按新内核重编一次。

**入口**：主界面第三行「换了固件 / 内核？」→「内核适配向导」。

### 符号从哪来（三条路，按省事程度排）

向导要的不是"某个文件"，是**符号地址表**。`target.h` 里每个宏都是
「符号地址 − `_text`」的**差值**——差值与 KASLR 无关、与内核有没有被 strip 无关、
与这个文件在不在设备上也无关。所以只要拿到名字→地址，就够了。

| 来源 | 怎么拿 | 大小 | 需要 root | 说明 |
|---|---|---|---|---|
| **`boot.img` / 裸 ARM64 Image**（首选） | 点「EDL 读 boot」，从 9008 直接读分区 | 96 MB | **不需要** | 符号表就编在 kernel 段的 `.rodata` 里，工具现场反解 |
| 设备上的 `/proc/kallsyms` | 手机插 USB，点「从设备读符号」 | 5~7 MB / 12 万行 | 需要 | 自动 `su` + 关 `kptr_restrict`，导完校验零地址比例 |
| `vmlinux.elf` | 厂商固件包 / 自己拼 | 60 MB+ | — | 带 `.symtab` 的未压缩 ELF。设备里不存在这个文件 |

### 没 root、网上又没有固件包，怎么拿到 boot.img

这条路是 9008 下载模式（高通 Sahara / Firehose）。设备进 9008 之后 Android
根本没启动，SELinux 和 Unix 权限模型都不在场，主机加载一个 firehose
programmer 就能按 GPT 表读任意分区。**不需要 root，也不需要 OTA 包或固件包。**

Leaf5 是 SM6350（lito），实测用 OnePlus N10 的 lito programmer 就能加载
（同 SoC 家族的通用 firehose 实现）。那份 programmer 在
[bkerler/Loaders](https://github.com/bkerler/Loaders) 里，文件名
`0013f0e100515198_2354228eebcbc203_fhprg_op_n10.bin`，`tools/fetch_deps.py` 自动下。

```bash
python edlman.py env      # 检查 edl 工具 / programmer / 9008 在线
python edlman.py slot     # 读当前运行槽（不需要 root）
python edlman.py dump -o out_dump
```

`dump` 的完整流程：

1. **定槽位** —— 先读 `getprop ro.boot.slot_suffix`（运行时事实），
   读不到再退回 GPT 里 `boot_*` 的 `Active` 标志
2. **进 9008** —— `adb reboot edl`，等 20 秒枚举
3. **读分区表** —— `printgpt`，拿到 80 个分区的 offset / length / Active
4. **只读目标槽** —— `r boot_b`，60 秒左右
5. **`reset` 回系统** —— 无论成败都会执行，否则设备一直黑屏停在下载模式

实测这台机器的分区表：

```
boot_a   off=0x028080000  len=0x006000000  Active False
boot_b   off=0x02E080000  len=0x006000000  Active True
super    off=0x034080000  len=0x180000000
```

**窗口期只有一次**：读出来的镜像必须过一遍 banner 校验（见下一节）。
A/B 设备上 `boot_b` 可能是上一个固件版本，读错槽等于偏移全错。

依赖都在外部，不打包进 EXE：[bkerler/edl](https://github.com/bkerler/edl)（USB 通信）
+ firehose programmer（[bkerler/Loaders](https://github.com/bkerler/Loaders) 里那份 `lito_op_n10_fhprg.bin`）
+ Windows 上给 `QUSB_BULK`（05C6:9008）绑 WinUSB（[Zadig](https://github.com/pbatard/libwdi/releases/tag/v1.5.1)）。
路径用环境变量覆盖：

```bash
LEAF5_EDL_DIR=E:\BOOX\edl-tool
LEAF5_EDL_PY=E:\BOOX\edl-venv\Scripts\python.exe
LEAF5_EDL_LOADER=E:\BOOX\loaders\lito_op_n10_fhprg.bin
```

不给环境变量时按「工具目录 → 上级目录 → `E:\BOOX\`」依次找。

如果设备上有残留的 OTA zip（`/sdcard/*.zip`），那是另一条路：解出
`payload.bin` 里的 boot 分区，同样不需要 root。但这条得先有包，多数机器 OTA
完就删了。

**先确认这个镜像是不是设备上正在跑的那个。** 设备是 A/B 双分区，
`boot_b.img` 很可能是上一个固件版本；同一台机器两次构建的偏移能差几万字节，
用它生成的 target.h 会让漏洞链打偏、在内核里随机位置崩。

判据是 `linux_banner`：内核启动时 `/proc/version` 打印的就是它，同一个字符串
还编在镜像里。两边的 git commit 一对就清楚。

```bash
python adapter.py banner boot_b.img
#   镜像 banner: 4.19.157-perf-g77c132eccfab-dirty ... #38 SMP PREEMPT ...
#   [i] 设备没连，跳过构建身份比对

python adapter.py banner boot_b.img --device "$(adb exec-out cat /proc/version)"
#   [X] 镜像 commit 77c132eccfab，设备 commit 3d47a6619220
#       这不是同一个内核 —— 换设备当前 boot 分区的镜像
```

四档结论：

| 结论 | 条件 | 怎么处理 |
|---|---|---|
| `same` | commit 与 build 号都相同、不带 `-dirty` | 直接用 |
| `resame` | commit 相同、build 号不同 | 同源码重编，`.config` 一致时偏移应相同；先验一遍 |
| `dirty` | 两边都对得上，但有一边带 `-dirty` | commit 代表不了二进制内容，只能当参考 |
| `different` | commit 不同 | **偏移必错**，换镜像 |

`gen` 会自己做这件事：设备连着且结论是 `different` 时直接拒绝生成
（要硬来就加 `--force`）。向导里选好文件就把 banner 显示在路径下面，
点「读设备指纹」时顺带跟设备的 `/proc/version` 对一次。

**为什么 boot 镜像就够了**：`/proc/kallsyms` 不是磁盘上的文件，是内核启动后把
编译进 `.rodata` 的四张表展开成的文本——`kallsyms_names`（token 压缩的符号名）、
`kallsyms_offsets`（相对 `_text` 的偏移）、`kallsyms_markers`、`kallsyms_token_table`。
这四张表原封不动躺在 boot 分区的 kernel 段里，反解一遍就得到同样的东西。

工具按结构自证一步步倒推（每一步都有独立校验，任何一步不成立就整体放弃）：

1. **token_index** — 256 个严格递增的 u16，首项 0，末项 < 16384
2. **token_table** — 紧邻其前的 256 个 `\0` 结尾短串，相邻两项必须首尾相接
3. **markers** — u64 单调递增，首项 0，末项 = names 区长度
4. **names 起点** — 用 markers 的字节偏移交叉验证，逐条解析到 markers 起点正好收尾
5. **offsets** — names 之前的 int32 数组，长 `N*4`，非递减，首项 0

手动版：

```bash
python adapter.py gen boot.img --repo <leaf5-ghostlock 仓库根>     # 直接吃 boot.img
python adapter.py gen kernel   --repo <leaf5-ghostlock 仓库根>     # 或裸 Image
python adapter.py gen syms.txt --repo <leaf5-ghostlock 仓库根>     # 或 kallsyms 文本
```

**三路实测逐位一致**：同一台设备，ELF（60,735,504 字节 Image 拼的）、
kallsyms 文本（121,896 行）、裸 Image 反解（121,896 条），提出来的 55 个宏
**差异 0**。反解耗时 0.67 秒（60 MB 镜像）。

```
token_index @ 0x2ED4900
token_table @ 0x2ED4500   长 943   末 token 't_'
markers     @ 0x2ED3600   477 项   末项 1652954
names       @ 0x2D3FA00   121896 条  长 1653760
offsets     @ 0x2CC8700   121896 条  末项 0x40A8000
→ 117009 个符号，_text = 0，commit_creds = 0x70FA0
```

**Magisk patch 过的 boot.img**：`magiskboot` 会把 kernel 解压成裸 Image，
再塞 `magiskinit` 进 ramdisk——kernel 段本身一字节不动，所以照样能反解。
（早期版本说这条路是死路，那是错的，已改。）

### 设备没 root、外部又拿不到任何文件时

这是常态。此时唯一的信息源是设备自身，而没 root 能读的东西里有一项被严重低估：

**`/proc/kallsyms` 在 `kptr_restrict=1` 时地址列全是 `0000000000000000`，
但符号名和排列顺序是完整的。** 内核只隐藏地址，不裁剪名字。

符号名序列对一次构建极其敏感——少一个 `CONFIG_*`、换个编译器、改一行内核代码，
序列都会变。所以「符号名序列的 sha256」几乎不会碰撞，而且**零权限**就能取。

向导里点「读设备指纹」（或 `python adapter.py fp`），采集：

| 项 | 用途 |
|---|---|
| `/proc/version` | 版本串 + build 号 + 构建时间 |
| `/proc/kallsyms` | **主判据**：符号名序列哈希 + 符号总数 |
| `getprop` | 型号、`ro.build.display.id`、verified boot 状态 |
| `/proc/modules` + 模块目录清单 | 旁证：厂商编了哪些 `.ko`，反映 CONFIG |
| `/proc/cmdline`、`/proc/zoneinfo`、`/proc/cpuinfo` | 槽位、内存布局、平台 |

结论只有三种，每种对应一个动作：

```
same_build     符号序列完全一致 → 直接用现成 preload.so，不用 root、不用重编
same_version   版本串同、序列不同 → 同版本的不同构建，必须 root 核实，不要硬试
different      都不匹配          → 陌生内核，必须 root 后重新适配
```

**不承诺的**：没 root 时反推绝对地址。地址清零后只剩顺序，没有间隔信息，
数学上不足以恢复地址。硬猜出来的偏移只会让内核在随机位置崩，
所以这里只做"认不认得出来"，不做"猜不猜得出"。

生成 target 时会自动存一份 `symfp.json`，`install` 时并进 `manifest.json`——
之后同一台设备（或同一次构建的任何一台）不用 root 就能被认出来。
主流程部署载荷前也会先读一次符号序列，本地有多份载荷时自动选对的那份。

### 打开就自动找

窗口一开就跑三级查找，不用手工翻目录：

1. **上次用过的** — `%LOCALAPPDATA%\Leaf5RootTool\recent_kernels.json`，
   记住上次选的那份，还在就直接填上（毫秒级）
2. **常见目录** — EXE 所在目录、当前目录、工具自己的目录、下载/桌面/文档，
   深度 3。约 0.3 秒
3. **全盘** — 前两级都没有才跑，非系统盘优先，深度 6，找到第一个带符号的就停。
   实测这台机器 0.5 秒命中

按钮栏右侧：「候选 N+M」展开清单（N = 带符号可用，M = 找到但用不上），
「全盘搜」强制全盘扫一遍（最多 180 秒，再点变「停止」可中断），
「从设备读符号」直接连手机拉一份。

扫描规则：只按扩展名（`.elf/.img/.bin/.map`）和文件名（含 vmlinux/kernel/boot/
image/kallsyms/system.map）筛，命中才读文件头判符号表。系统目录（Windows、
AppData、Program Files、node_modules 等）直接跳过。故意不收 `.txt`——
全盘几十万个 txt 每个都读头部，代价远大于收益；用户手动指定的文件不受此限制。

### 五步

1. **内核** — 打开向导时已自动填好；要换就点「候选」「浏览…」，
   或用「从设备读符号」直接拉一份
2. **等 NDK** — 本机有 Android SDK 就直接复用（自动扫 `ANDROID_HOME` /
   `%LOCALAPPDATA%\Android\Sdk`）；没有就点「下载 NDK」
   （[ndkman.py](ndkman.py) 按 r29 → r27c 试
   [Google 的 NDK 包](https://developer.android.com/ndk/downloads)），约 700 MB，
   解压 3.6 GB，完事自动裁剪到 1.6 GB（只删 sources、另两个平台的 prebuilt 之类，
   `bin/` 一个文件不动）
3. **生成 target.h** — 自动提 55 个符号偏移，写出 `targets/migr-xxxx/target.h`
4. **填 4 个值** — 符号表里没有的，必须人工
5. **编译 → 装进工具** — 产物落到 `%LOCALAPPDATA%\Leaf5RootTool\targets\<id>\`，
   带设备指纹；之后主界面遇到同指纹的设备会自动选它

### 差异表怎么读

生成时会列出「模板值 vs 本机 vmlinux 值」：

- **0 个差异** → 这份 vmlinux 就是模板对应的构建，编出来应与出厂载荷逐字节一致
- **几个到十几个差异** → 同系列不同构建，正常。全部采用符号表的值
- **全部差异** → 换大版本了，属于移植级，4 个手工值尤其要仔细

### 4 个手工值怎么取

| 宏 | 取法 |
|---|---|
| `TASK_CRED_OFF` | 反汇编 `commit_creds`，找 `ldr x8, [x19, #0x7e0]` 那个立即数 |
| `WAITER_LOCAL_OFF` | `rt_mutex_waiter` 里 `task` 字段的偏移。本机 0x50（多了 prio+deadline），主线 4.19 是 0x40 |
| `PRCTL_FRAME_TOTAL` | `__arm64_sys_prctl` 开头的 `stp x29,x30,[sp,#-0x..]!` + `sub sp,sp,#0x..` 之和 |
| `PRCTL_WAITER_WORD_DEFAULT` | 必须 panic 定标：`PRCTL_POISON=1` 跑一次，从崩溃现场 x21 反推 `(0x340-0x38-8*i)/8` |

填完前工具拒绝编译（`target.h` 里有 `/*FILL_ME*/` 就不让过）。

### 自证

编译完会打印 md5 和尺寸。拿**原版 target.h** 编一次，应该是
`6f36e1e889e0d05aa2fd9d93f3771168` / `2494504` 字节 —— 这就是出厂载荷，
对得上说明整条链路（NDK、incbin、符号替换）都是对的。

### 命令行等价操作

```bash
# 0) 先认设备：不用 root，判断该不该用现成载荷
python adapter.py fp          # 采集 + 保存指纹包 + 直接给结论
python adapter.py match device-fp-20261029-1923.json   # 回头复查

# 首选：直接连设备拉符号（设备已 root）
python adapter.py kallsyms -o syms.txt
python adapter.py gen syms.txt --repo <leaf5-ghostlock 仓库根>

# 或者直接喂 boot.img —— 内部切 kernel 段、解压、反解 kallsyms 一条龙
python adapter.py gen boot.img --repo <leaf5-ghostlock 仓库根>

# 后面的步骤两条路一样
python adapter.py build <repo>/exploit/targets/migr-xxx --repo <仓库根> -o preload.so
python adapter.py install preload.so --id migr-xxx --fingerprint <设备指纹>
python adapter.py list
```

`gen` 的输入是"符号来源"，`boot.img` / 裸 ARM64 Image / `.elf` / kallsyms 文本
四种都吃，自动识别。前两种不需要 root，也不需要任何外部文件。

### 两个坑（都已处理，改代码时别改回去）

- `su_daemon` 必须 `-static`。动态版只有 15 KB，推到设备上没有对应 linker 路径，
  跑不起来。静态版 2251616 字节。
- `.incbin` 的相对路径解析基准在 clang 上不唯一（实测 cwd 优先、源文件目录兜底），
  所以 su_daemon 会往两个位置各放一份，否则会嵌进上一次编译的旧文件。

---

## 目录

```
roottool.py             主程序（GUI + 流程）
adapter.py              内核适配流水线（解 vmlinux / 提符号 / 生成 target.h / 编译）
adapter_ui.py           适配向导窗口
autopilot.py            一键全自动的编排层（等设备 → 适配 → 编译）
fp.py                   无 root 设备指纹采集与匹配（符号名序列哈希）
imageksym.py            裸 ARM64 Image 的 kallsyms 反解（token 表 + 偏移数组）
a64.py                  极简 ARM64 解码器（只为推 TASK_CRED_OFF / PRCTL_FRAME_TOTAL）
elfsyms.py              纯标准库 ELF64 符号表解析 + kallsyms 文本解析
ndkman.py               NDK 查找 / 下载 / 解压 / 校验 / 裁剪
drivers.py              Zadig 驱动引导（新机器缺 WinUSB 时）
build.py                打包脚本

edlmain.py              firehose 协议层（USB / 串口 / 网络三种后端）
edllink.py              9008 会话封装（programmer 选择、4MB 分块读、校验重读）
edlman.py               EDL 子命令：env / slot / gpt / dump / r
usbtrace.py             USB 侧实况，绕开 adb 直接问 SetupAPI
edlclient/              vendored 的 bkerler/edl（去了 .git，只留 Library/Config/Tools）

assets/                 运行时资源
  exploit_src/          exploit 源码树，适配向导现编 preload.so 用（在仓库里）
  payload/device_root.sh 设备端自持脚本（在仓库里）
  adb/ magisk/ *.bin zadig.exe payload/preload.so   ← 自己按下面的表放

build/                  PyInstaller 的 spec 与版本资源
_test_dump/             guard 闸门与 GUI 的离线自测（不接设备也能跑）
```

运行时会在 `%LOCALAPPDATA%\Leaf5RootTool\` 下铺 `bin\`（adb）、`logs\`、
`src\`（适配工作区）、`targets\`（适配出来的载荷）、`ndk\`（下载的 NDK）。

---

## 自己重新打包

```bash
python tools/fetch_deps.py   # 拉齐 assets 下缺的二进制（带 sha256 校验）
python build.py              # 单文件，产物 dist/Leaf5RootTool.exe
python build.py --sign       # 打包后签名
python build.py --onedir     # 目录版，启动快
```

`build.py` 缺文件时会直接报路径，并区分「能自动下的」和「只能自己产的」
—— 前者一条 `fetch_deps.py` 解决，后者是 `preload.so`。

必须用带 tkinter 的 64 位 Python（微软商店那个精简版没有，PyInstaller
不会报错，会安安静静打出一个启动就崩的包）。

Python 依赖：

```bash
pip install pyinstaller pyusb pyserial libusb-package docopt capstone colorama
```

### assets 里的二进制不进仓库

体积 + 授权两个原因。目录已经在仓库里（`.gitkeep` 占位）。两条路：

**自动**（推荐）：

```bash
python tools/fetch_deps.py           # 缺什么下什么，逐件 sha256 校验
python tools/fetch_deps.py --check   # 只看缺什么，不下载
python tools/fetch_deps.py --no-zadig
```

能自动下的有七件：adb 三件、Magisk、`lito_op_n10_fhprg.bin`、`lito_moto_fhprg.bin`、zadig。
下完立即校验，对不上就删掉报错 —— 不会留下一个"看着在、其实是 404 页面"的文件。
`adb` 钉的是 platform-tools **r37.0.0**（`-latest` 会漂移，r37.0.1 的三个文件
哈希与下面这组全都不同，实测过）。

**手动**：按下面这张表自己放 —— `build.py` 开头会逐个检查，缺哪个直接报路径：

| 放哪 | 从哪拿 | 自动 | sha256 |
|---|---|---|---|
| `assets/adb/adb.exe` | [platform-tools r37.0.0](https://dl.google.com/android/repository/platform-tools_r37.0.0-win.zip) | ✅ | `957e46b8615f7af5b7292a2ddabe98d2e61940c3fb2b0545756507f080613e71` |
| `assets/adb/AdbWinApi.dll` | 同上（zip 里 `platform-tools/`） | ✅ | `120bef587119c6cb926b86b9be90fdfbce38937588eae28cd91a94ce63c7b965` |
| `assets/adb/AdbWinUsbApi.dll` | 同上 | ✅ | `6ca69a2ca0e31309c087d288f058977d421ad03500e4c3e1dbd981241a069c60` |
| `assets/magisk/Magisk-v31.1.apk` | [Magisk v31.1](https://github.com/topjohnwu/Magisk/releases/download/v31.1/Magisk-v31.1.apk) | ✅ | `89cefac0a318afa39fb3880c45c87b036c05bc1ebf02a7a715b7f8d7c26ac6e7` |
| `assets/zadig.exe` | [libwdi v1.5.1 → zadig-2.9.exe](https://github.com/pbatard/libwdi/releases/download/v1.5.1/zadig-2.9.exe) | ✅ 可选 | `4ecaa95df3da3621486a043aef8b3050b8bafe7c901402871e816229ef82039b` |
| `assets/lito_op_n10_fhprg.bin` | [bkerler/Loaders → op_n10](https://raw.githubusercontent.com/bkerler/Loaders/main/oneplus/0013f0e100515198_2354228eebcbc203_fhprg_op_n10.bin) | ✅ | `6558f49c3a55d0eb7fdd7bb326c9bb22b29f4b6b6316937e847e8b76e11f6ec0` |
| `assets/lito_moto_fhprg.bin` | [bkerler/Loaders → moto lito](https://raw.githubusercontent.com/bkerler/Loaders/main/lenovo_motorola/0013f0e102e80000_628be3f403d0c67a_fhprg.bin)（文件名前缀就是 HWID `0013f0e1` + OEM `02e8`） | ✅ 可选 | `1b5fa0ac18e3ac136aac184bf36d4ef02ad1819ccadc14214b97ce00326e20c1` |
| `assets/payload/preload.so` | 编译产物 —— 装好 EXE 后向导现编，产物在包外、**不用重打 EXE**，见下 | ❌ | `5acbe2003ea451f575bb6a9be07f2b0d75218103cd91f2ef5a34467fd823bd6e` |
| `assets/payload/device_root.sh` | 已在仓库里（纯文本脚本） | — | `3724942215bfc91c45feeeebe7952b28c777e87c21ec6dbe48684ed51d320c92` |

`assets/exploit_src/exploit/` 是 C 源码树，`build.py:sync_exploit()` 每次
打包前从 `EXPLOIT_REPO`（默认 `../leaf5-ghostlock/exploit`，见
[350886/leaf5-ghostlock](https://github.com/350886/leaf5-ghostlock)）同步过来，
已有副本可以直接用。

**`preload.so` 是编出来的，不是下下来的。** 62 个偏移只对「原厂 4.2.3 + 这一版
`target.h`」成立，别人机器编出来的是另一份，拷过来跑不了。

### 装好 EXE，第一次先跑「内核适配向导」（不用重打 EXE）

**这一步跟「重新编译 Leaf5RootTool.exe」没关系。** 向导只产出 `preload.so` 一个文件，
落在包外，工具下次启动自己去捡 —— 不重打也生效。

别急着点「一键全自动」：

1. 主界面点「内核适配向导」
2. 五步走完：选内核 → 等 NDK → 生成 `target.h` → 填 4 个值 → 编译装进工具
3. 产物落在 `%LOCALAPPDATA%\Leaf5RootTool\targets\<id>\preload.so`，带设备指纹
4. 回主界面，遇到同指纹的设备会自动选这份，不用再指定

适配结果是包外的一个目录，APP 每次部署都重新扫：
传进来的载荷 → `targets\` 里指纹/符号序列对得上的 → 都没命中才用包内
`assets/payload/preload.so`（`roottool.py:751-788`）。所以内置那份不准也照样能跑，
向导补上就行。

自己这台要不要编，先看内核串：

```bash
adb shell uname -r
```

回 `4.19.157-perf-g77c132eccfab-dirty` 说明和内置那份对得上，编出来应与它逐字节
一致；不是这个串就必须现编，否则偏移是错的。

内核怎么来，分两条路：

```bash
# ① 设备已经 root：向导第 1 步点「从设备读符号」
#    它 su 进设备读 /proc/kallsyms，不需要固件包

# ② 设备还没 root：先用上面那个 programmer 进 9008 读 boot
Leaf5RootTool.exe --edl dump -o out_dump      # 产出 out_dump\boot_b.img
#    然后在向导里选这个 boot_b.img —— 它反解符号后调 NDK 现编
```

`-o` 是**目录**不是文件名，输出固定叫 `boot_a.img` / `boot_b.img`（按实际槽位）。
完整流程（定槽位 → 进 9008 → printgpt → 读分区 → reset）见「内核适配」那节。

### 只有想把 .so 一起打进 EXE 里，才需要重打一次

`build.py:142` 检查 `assets/payload/` 下两个文件在不在，因为那是打进包里的兜底。
顺序反过来走一遍：

```bash
python tools/fetch_deps.py        # 先拉齐其它六件
python roottool.py                # 还没有 EXE 时，用源码起界面
#   点「内核适配向导」→ 编完 → 产物在 targets\<id>\preload.so

cp "%LOCALAPPDATA%\Leaf5RootTool\targets\<id>\preload.so" assets\payload\preload.so
python build.py --sign
```

也就是说 **EXE 里那份，是上一次跑适配向导的产出**。别人的产物别往自己包里塞 ——
`target.h` 不同，那份 `.so` 只在他那台机器上跑得对。

**`lito_moto_fhprg.bin` 从哪来**：就是
[bkerler/Loaders](https://github.com/bkerler/Loaders) 里
`lenovo_motorola/0013f0e102e80000_628be3f403d0c67a_fhprg.bin`。
文件名前半段 `0013f0e1` 是 HW_ID、`02e8` 是 OEM_ID —— 与 Leaf5 要的
`HW_ID 0013F0E1` 一字不差，所以它能在 Leaf5 上跑起来；后半段
`628be3f403d0c67a` 是这枚 firehose 自己的构建指纹。

它是 Motorola PKI 签的（`strings` 里能看到 `Motorola Attestation CA 719`），
EDL 的 firehose 握手只认 HW_ID、不校验签名方，所以与 OnePlus 那份同样能用。
两份体积不同（759,536 vs 765,440 字节），差的是各自的证书链。

`loader_candidates()` 里 op_n10 那份排第一（实测通过），摩托这份只是兜底；
`fetch_deps.py` 会把它一起下。缺了不影响 9008 通路。

