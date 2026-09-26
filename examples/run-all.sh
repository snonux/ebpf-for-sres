#!/bin/bash
# Runs every example from the eBPF intro deck and reports PASS/FAIL.
# Usage: sudo ./run-all.sh
# Needs: bpftrace, bcc-tools, bpftool, clang, llvm, libbpf-devel, gcc, make
#        (see setup-rocky9.sh). Each tracing example runs for $SECS seconds
#        while workload.sh generates file I/O.
set -u
cd "$(dirname "$0")"
SECS=${SECS:-5}
LOG=${LOG:-run-all.log}
pass=0; fail=0
: > "$LOG"

if [ "$(id -u)" -ne 0 ]; then
    echo "Run as root: sudo $0"; exit 1
fi

result() {
    if [ "$1" -eq 0 ]; then echo "PASS  $2"; pass=$((pass + 1))
    else echo "FAIL  $2  (see $LOG)"; fail=$((fail + 1)); fi
}

# Runs a bpftrace script for $SECS seconds under load. It passes when the probes
# attach, the program exits cleanly on SIGINT, and it printed some output.
run_bt() {
    local script=$1
    echo "===== $script" >> "$LOG"
    bash workload.sh $((SECS + 3)) &
    local load=$!
    local src=$script
    # bpftrace older than 0.20 only knows args->name, not args.name.
    if ! bpftrace -e 'BEGIN { exit(); } tracepoint:syscalls:sys_enter_openat { printf("%s", str(args.filename)); }' >/dev/null 2>&1; then
        sed 's/args\./args->/g' "$script" > compat.bt; src=compat.bt
    fi
    timeout -s INT "$SECS" bpftrace "$src" > out.tmp 2>&1
    local status=$?
    wait "$load"
    cat out.tmp >> "$LOG"
    local lines attached=0
    lines=$(grep -vcE '^(Attaching|WARNING|ERROR: Unknown error -1: couldn.t set RLIMIT|$)' out.tmp)
    grep -q '^Attaching' out.tmp && attached=1
    rm -f out.tmp compat.bt
    [ "$status" -eq 0 ] || [ "$status" -eq 124 ] || return 1
    [ "$attached" -eq 1 ] && [ "$lines" -gt 0 ]
}

echo "Kernel: $(uname -r)   $(grep PRETTY_NAME /etc/os-release | cut -d= -f2)"
echo "bpftrace: $(bpftrace --version 2>&1)"
echo

for s in 01-opens-per-process.bt 02-opensnoop.bt 03-syscalls-per-process.bt \
         04-read-size-hist.bt 05-read-latency.bt 05b-vfs-read-latency-kprobe.bt; do
    run_bt "$s"; result $? "$s"
done

echo "===== 06-list-probes.sh" >> "$LOG"
bash 06-list-probes.sh >> "$LOG" 2>&1 && grep -q 'sys_enter_openat' "$LOG"
result $? "06-list-probes.sh"

echo "===== libbpf example" >> "$LOG"
(
    cd libbpf && make clean >/dev/null && make &&
    { bash ../workload.sh $((SECS + 3)) & ./count_writes "$SECS"; wait; } &&
    bpftool btf dump file /sys/kernel/btf/vmlinux format c > /dev/null
) > libbpf.tmp 2>&1
status=$?
cat libbpf.tmp >> "$LOG"
[ "$status" -eq 0 ] && grep -qE '^[0-9]+ +[^ ]+ +[0-9]+$' libbpf.tmp
result $? "libbpf/count_writes (build, load, attach, read map)"
rm -f libbpf.tmp

echo "===== 07-bcc-tools.sh" >> "$LOG"
bash workload.sh $((SECS * 8)) &
load=$!
bash 07-bcc-tools.sh "$SECS" >> "$LOG" 2>&1
result $? "07-bcc-tools.sh (execsnoop opensnoop biolatency runqlat tcplife tcpretrans profile)"
wait "$load"

echo
echo "$pass passed, $fail failed. Full output: $LOG"
[ "$fail" -eq 0 ]
