#!/bin/bash
# Runs every example and reports PASS/FAIL/SKIP per variant.
#
#   sudo ./run-all.sh                 bpftrace and shell examples
#   sudo GO=1 ./run-all.sh            also builds and tests every Go (libbpfgo) version with mage
#   sudo SECS=10 ./run-all.sh         run each tracing example longer
#
# Setup: ./setup-rocky9.sh (add --go for the Go toolchain).
# Each tracing example runs for $SECS seconds while workload.sh generates file
# I/O and DNS lookups. Full output goes to run-all.log.
set -u
cd "$(dirname "$0")"
# sudo resets PATH on Rocky; mage is installed to /usr/local/bin by setup-rocky9.sh.
export PATH=$PATH:/usr/local/bin:/usr/local/go/bin
SECS=${SECS:-5}
GO=${GO:-0}
LOG=$PWD/${LOG:-run-all.log}
pass=0; fail=0; skip=0
: > "$LOG"

if [ "$(id -u)" -ne 0 ]; then
    echo "Run as root: sudo $0"; exit 1
fi

result() {
    case $1 in
        0) echo "PASS  $2"; pass=$((pass + 1)) ;;
        77) echo "SKIP  $2  ($3)"; skip=$((skip + 1)) ;;
        *) echo "FAIL  $2  (see $LOG)"; fail=$((fail + 1)) ;;
    esac
}

# bpftrace older than 0.20 only knows args->name, not args.name.
compat=0
bpftrace -e 'BEGIN { exit(); } tracepoint:syscalls:sys_enter_openat { printf("%s", str(args.filename)); }' \
    >/dev/null 2>&1 || compat=1

# Runs a tracer for $SECS seconds under load. It passes when the probes attach,
# the program exits cleanly on SIGINT, and it printed something.
run_traced() {   # name, command...
    local name=$1; shift
    echo "===== $name" >> "$LOG"
    bash workload.sh $((SECS + 3)) &
    local load=$!
    sleep 0.5
    timeout -s INT "$SECS" "$@" > out.tmp 2>&1
    local status=$?
    wait "$load"
    head -40 out.tmp >> "$LOG"   # streaming examples print thousands of lines
    local lines
    lines=$(grep -vcE '^(Attaching|WARNING|ERROR: Unknown error -1: couldn.t set RLIMIT|Pass [0-9]|$)' out.tmp)
    rm -f out.tmp
    [ "$status" -eq 0 ] || [ "$status" -eq 124 ] || return 1
    [ "$lines" -gt 0 ]
}

run_bt() {
    local src=$1
    if [ "$compat" -eq 1 ]; then
        sed 's/args\./args->/g' "$1" > compat.bt; src=compat.bt
    fi
    run_traced "$1" bpftrace "$src"
    local rc=$?
    rm -f compat.bt
    return $rc
}

echo "Kernel: $(uname -r)   $(grep PRETTY_NAME /etc/os-release | cut -d= -f2)"
echo "bpftrace: $(bpftrace --version 2>&1)"
[ "$GO" = 1 ] && echo "go: $(go version 2>&1)"
echo

for dir in [0-9][0-9]-*/; do
    dir=${dir%/}
    for bt in "$dir"/*.bt; do
        [ -e "$bt" ] || continue
        run_bt "$bt"; result $? "$bt"
    done
    if [ -f "$dir/magefile.go" ]; then
        if [ "$GO" = 1 ]; then
            echo "===== $dir: mage test" >> "$LOG"
            (cd "$dir" && mage test) > out.tmp 2>&1
            status=$?
            tail -40 out.tmp >> "$LOG"; rm -f out.tmp
            result $status "$dir (Go, libbpfgo)"
        else
            result 77 "$dir (Go, libbpfgo)" "set GO=1"
        fi
    fi
done

echo "===== 08-list-probes/list-probes.sh" >> "$LOG"
bash 08-list-probes/list-probes.sh > out.tmp 2>&1; status=$?
cat out.tmp >> "$LOG"
[ "$status" -eq 0 ] && grep -q 'sys_enter_openat' out.tmp
result $? "08-list-probes/list-probes.sh"; rm -f out.tmp

echo "===== 09-bcc-tools/bcc-tools.sh" >> "$LOG"
bash workload.sh $((SECS * 8)) &
load=$!
bash 09-bcc-tools/bcc-tools.sh "$SECS" >> "$LOG" 2>&1
result $? "09-bcc-tools/bcc-tools.sh (execsnoop opensnoop biolatency runqlat tcplife tcpretrans profile)"
wait "$load"

echo "===== 10-overhead-drops/overhead.sh" >> "$LOG"
bash 10-overhead-drops/overhead.sh "$SECS" > out.tmp 2>&1
status=$?
cat out.tmp >> "$LOG"
[ "$status" -eq 0 ] && grep -q 'ns/run' out.tmp
result $? "10-overhead-drops/overhead.sh"; rm -f out.tmp

echo "===== 11-count-writes: C loader (make)" >> "$LOG"
(
    cd 11-count-writes && make clean >/dev/null && make &&
    { bash ../workload.sh $((SECS + 3)) & ./count_writes_c "$SECS"; wait; }
) > out.tmp 2>&1
status=$?
cat out.tmp >> "$LOG"
[ "$status" -eq 0 ] && grep -qE '^[0-9]+ +[^ ]+ +[0-9]+$' out.tmp
result $? "11-count-writes (C, libbpf: build, load, attach, read map)"; rm -f out.tmp

echo
echo "$pass passed, $fail failed, $skip skipped. Full output: $LOG"
[ "$fail" -eq 0 ]
