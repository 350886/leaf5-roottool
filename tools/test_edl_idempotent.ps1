# test_edl_idempotent.ps1 —— 不刷机验证 EDL(9008) 的写 boot 通路
#
# 原理：幂等写入。
#   把设备当前的 boot 分区读出来当源镜像，再经 EDL 原样写回去。
#   写进去的每个字节都等于该位置原值 ⇒ 分区内容一字节不变；
#   中途掉电也不会坏（已写的是原值，没写的还是原值）。
#   但写入路径是完整跑了一遍：GPT 校验 → 容量校验 → 备份 → 写 → 读回比 sha256 → reset。
#
# 四步（A/B/C 是一组哈希，三个都相等才算通过）：
#   1. root 下 dd 读 boot 分区           → sha256 A（金标准）
#   2. EDL 读同一分区                     → sha256 B，断言 A == B（证明读路径对）
#   3. EDL 把 B 原样写回                  → 工具自带读回校验
#   4. reset 回系统，dd 再读一次           → sha256 C，断言 A == C（证明写回来没变）
#
# 用法：
#   pwsh -File tools\test_edl_idempotent.ps1              # 完整四步
#   pwsh -File tools\test_edl_idempotent.ps1 -ReadOnly    # 只做 1、2 步，一个字节不写
#   pwsh -File tools\test_edl_idempotent.ps1 -Part boot_a # 指定分区（默认按当前槽推）
#
# 会黑屏重启两次（第 2、3 步各进一次 9008），每次 3~6 分钟。
# 前提：电量 > 50%，USB 全程不松，设备已 root。

param(
    [string]$Part = "",
    [switch]$ReadOnly,
    [switch]$KeepFiles
)

$ErrorActionPreference = "Stop"
$here = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$adb  = Join-Path $here "assets\adb\adb.exe"
$exe  = Join-Path $here "dist\Leaf5RootTool.exe"
$work = Join-Path $here "work\_edl_test"

foreach ($p in @($adb, $exe)) {
    if (-not (Test-Path $p)) { throw "缺文件：$p" }
}
New-Item -ItemType Directory -Force -Path $work | Out-Null

function Say($t, $c = "Gray") { Write-Host $t -ForegroundColor $c }
function Rule { Say ("-" * 62) DarkGray }

function Hash($path) {
    if (-not (Test-Path $path)) { throw "文件不存在：$path" }
    (Get-FileHash $path -Algorithm SHA256).Hash.ToLower()
}

function Wait-Adb([int]$seconds = 180) {
    $end = (Get-Date).AddSeconds($seconds)
    while ((Get-Date) -lt $end) {
        $out = (& $adb devices 2>&1) -join " "
        if ($out -match "\sdevice(\s|$)") { return $true }
        & $adb reconnect offline 2>&1 | Out-Null
        Start-Sleep -Seconds 3
    }
    return $false
}

# 在 root shell 里跑一条命令。su -c 的引号必须整体交给设备 shell，
# 否则 PowerShell 和 sh 各剥一层，dd 的参数会被吃掉。
function Root-Sh([string]$cmd) {
    & $adb shell "su -c '$cmd'" 2>&1
}

# 从分区读一份镜像到本地。
#
# 为什么分块：实测这台机器一次 adb pull 96MB 会在 42% 左右断线（报
# no devices / offline），而且 adb server 会跟着一起卡死。分 32MB 一块，
# 断开就 reconnect 重试，单块失败不影响已拿到的部分。
function Get-PartImage([string]$partName, [string]$outFile, [int]$totalBytes) {
    $chunk = 32MB
    $tmp   = "/data/local/tmp/_edl_chunk.bin"
    $fs = [IO.File]::Create($outFile)
    try {
        $off = 0
        $idx = 0
        while ($off -lt $totalBytes) {
            $mb = [Math]::Floor($off / 1MB)
            Root-Sh "rm -f $tmp" | Out-Null
            $dd = Root-Sh "dd if=/dev/block/by-name/$partName of=$tmp bs=1M skip=$mb count=32"
            $local = Join-Path $work ("_chunk$idx.bin")
            $ok = $false
            for ($try = 0; $try -lt 4; $try++) {
                if (Test-Path $local) { Remove-Item $local -Force }
                $null = & $adb pull $tmp $local 2>&1
                if ((Test-Path $local) -and $LASTEXITCODE -eq 0) {
                    if ((Get-Item $local).Length -gt 0) { $ok = $true; break }
                }
                & $adb reconnect offline 2>&1 | Out-Null
                Start-Sleep -Seconds 2
            }
            if (-not $ok) { throw "第 $idx 块读不出来（offset $off）" }
            $bytes = [IO.File]::ReadAllBytes($local)
            $fs.Write($bytes, 0, $bytes.Length)
            $off += $bytes.Length
            Say ("   块 {0}  已读 {1:N0}/{2:N0} 字节" -f $idx, $off, $totalBytes) DarkGray
            Remove-Item $local -Force
            $idx++
        }
    } finally {
        $fs.Close()
        Root-Sh "rm -f $tmp" | Out-Null
    }
    return (Get-Item $outFile).Length
}

# ---------- 0. 前置检查 ----------
Rule
Say "0) 前置检查" Cyan
if (-not (Wait-Adb 20)) { throw "adb 里没有设备。先连上 USB、打开 USB 调试。" }

$model = ((& $adb shell getprop ro.product.model 2>&1) -join "").Trim()
$uid   = (Root-Sh "id") -join ""
if ($uid -notmatch "uid=0") { throw "su 不可用（返回：$uid）。这个测试要在已 root 的设备上跑。" }

$slot = ((& $adb shell getprop ro.boot.slot_suffix 2>&1) -join "").Trim()
if (-not $Part) {
    $Part = if ($slot) { "boot$slot" } else { "boot" }
}
# 从 GPT 的 by-name 链接拿真实大小，比先读一遍再问要便宜
$sz = (Root-Sh "blockdev --getsize64 /dev/block/by-name/$Part") -join ""
$total = 0
if ($sz -match "(\d{6,})") { $total = [int64]$Matches[1] }
Say ("   设备    : " + $model)
Say ("   槽位    : " + $(if ($slot) { $slot } else { "（非 A/B）" }))
Say ("   目标分区: $Part  ($([math]::Round($total/1MB,1)) MB)")
Say ("   模式    : " + $(if ($ReadOnly) { "只读（不写）" } else { "幂等写回" }))

# ---------- 1. dd 取基准 ----------
Rule
Say "1) 从系统内 dd 读 $Part（金标准）" Cyan
$baseLocal = Join-Path $work "base_dd.img"
Get-PartImage $Part $baseLocal $total | Out-Null

$sizeA = (Get-Item $baseLocal).Length
$hashA = Hash $baseLocal
Say ("   大小    : {0:N0} 字节（{1:N1} MB）" -f $sizeA, ($sizeA / 1MB))
Say ("   sha256 A: $hashA") Green

# 头部自证：不是 ANDROID! 就说明分区读错了，后面写的也是垃圾
$fs = [IO.File]::OpenRead($baseLocal)
$hdr = New-Object byte[] 8
$fs.Read($hdr, 0, 8) | Out-Null
$fs.Close()
$magic = [Text.Encoding]::ASCII.GetString($hdr)
Say ("   头部    : $magic")
if ($magic -ne "ANDROID!") {
    Say "   [!] 头不是 ANDROID!。可能这个机型的分区名不是 $Part，停在这里，什么都没写。" Yellow
    throw "分区头不对，已中止"
}

# ---------- 2. EDL 读 ----------
Rule
Say "2) 经 EDL(9008) 读同一分区 —— 设备会黑屏重启" Cyan
$edlLocal = Join-Path $work "boot_edl.img"
if (Test-Path $edlLocal) { Remove-Item $edlLocal -Force }

& $exe --edl r $Part -o $edlLocal
if (-not (Test-Path $edlLocal)) {
    throw "EDL 读没产出文件，看 %LOCALAPPDATA%\Leaf5RootTool\logs\edl_*.log"
}

$sizeB = (Get-Item $edlLocal).Length
$hashB = Hash $edlLocal
Say ("   大小    : {0:N0} 字节" -f $sizeB)
Say ("   sha256 B: $hashB") Green

if ($hashB -eq $hashA) {
    Say "   [OK] A == B，EDL 读路径正确" Green
} else {
    Say "   [X] A != B。EDL 读出来的和系统内读的不一样，读路径有问题，不再往下走。" Red
    Say "       常见原因：这个分区在别的 LUN 上（programmer 的 lun 参数），或者读的时候分了片但没接上。" Yellow
    throw "读路径校验失败，未写入任何字节"
}

if ($ReadOnly) {
    Rule
    Say "只读模式，到此为止。分区一个字节没动。" Green
    if (-not $KeepFiles) { Remove-Item $baseLocal, $edlLocal -Force -ErrorAction SilentlyContinue }
    return
}

# ---------- 3. EDL 幂等写回 ----------
Rule
Say "3) 把刚才读出来的这份原样写回去 —— 设备会再黑屏重启一次" Cyan
Say "   写的是 B，而 B == A，所以分区内容不会变。" DarkGray

& $exe --edl w $Part $edlLocal --yes
if ($LASTEXITCODE -ne 0) {
    Say "   [X] 写入返回 $LASTEXITCODE，看日志。" Red
    Say "       如果工具报「已回滚」，说明它自己刷回备份了，分区仍是原样。" Yellow
    throw "写入失败"
}
Say "   [OK] 写入 + 读回校验由工具完成（不符会自动回滚并报错）" Green

# ---------- 4. 重启后再读一次 ----------
Rule
Say "4) 等设备回系统，dd 再读一次对账" Cyan
if (-not (Wait-Adb 240)) {
    Say "   180 秒内没等到 adb。" Red
    Say "   设备可能还停在 9008：长按电源键 15 秒，或者拔插一次 USB。" Yellow
    throw "设备没回系统"
}

$afterLocal = Join-Path $work "after_dd.img"
Get-PartImage $Part $afterLocal $total | Out-Null
$hashC = Hash $afterLocal
Say ("   sha256 C: $hashC") Green

# ---------- 结论 ----------
Rule
Say "结论" Cyan
Say ("   A (dd 基准)     : $hashA")
Say ("   B (EDL 读出)    : $hashB")
Say ("   C (写回后再读)  : $hashC")
Say ""
if (($hashA -eq $hashB) -and ($hashA -eq $hashC)) {
    Say "   三项一致 —— EDL 的读、写、幂等全部验证通过，分区内容未变。" Green
} else {
    Say "   有不一致项，别继续用这台设备做别的写入前先查清楚。" Red
}

if (-not $KeepFiles) {
    Remove-Item $baseLocal, $edlLocal, $afterLocal -Force -ErrorAction SilentlyContinue
    Say "`n   （镜像已清理，加 -KeepFiles 保留在 work\_edl_test\）" DarkGray
} else {
    Say "`n   镜像保留在 $work" DarkGray
}
