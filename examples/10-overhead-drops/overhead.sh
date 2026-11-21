#!/bin/bash
# 10: what a BPF program costs. With kernel.bpf_stats_enabled=1 the kernel
# counts runs and nanoseconds per program; bpftool prints them.
# Run: sudo ./overhead.sh [seconds]   (default 5)
set -u
secs=${1:-5}
cd "$(dirname "$0")"
old=$(sysctl -n kernel.bpf_stats_enabled)
sysctl -qw kernel.bpf_stats_enabled=1
trap 'sysctl -qw kernel.bpf_stats_enabled=$old' EXIT

bash ../workload.sh $((secs + 2)) &
bpftrace -e 'tracepoint:raw_syscalls:sys_enter { @[comm] = count(); }' > /dev/null &
bt=$!
sleep "$secs"
echo "== Programs loaded right now, with run_time_ns and run_cnt:"
bpftool prog show | grep -A2 -E 'tracepoint|kprobe' | grep -B1 -A1 run_cnt || bpftool prog show
echo
echo "== Average cost per run of the bpftrace counting program:"
bpftool prog show -j | python3 -c '
import json, sys
for p in json.load(sys.stdin):
    if p.get("run_cnt"):
        print("%-24s %10d runs %8.0f ns/run" % (p.get("name", "?"), p["run_cnt"], p["run_time_ns"] / p["run_cnt"]))
'
kill -INT $bt
wait
