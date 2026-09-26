#!/bin/bash
# Toolbox slide: run each ready-made bcc tool for a few seconds.
# Rocky/RHEL: dnf install bcc-tools  (tools live in /usr/share/bcc/tools)
# Debian/Ubuntu: apt install bpfcc-tools (tools are named <tool>-bpfcc)
# Usage: sudo ./07-bcc-tools.sh [seconds per tool]   (default 5)
set -u
secs=${1:-5}
rc=0

find_tool() {
    if [ -x "/usr/share/bcc/tools/$1" ]; then
        echo "/usr/share/bcc/tools/$1"
    elif command -v "$1-bpfcc" >/dev/null 2>&1; then
        command -v "$1-bpfcc"
    fi
}

# Runs a tool, stops it with SIGINT after $secs (histogram tools print on SIGINT).
run_tool() {
    local name=$1; shift
    local bin
    bin=$(find_tool "$name")
    if [ -z "$bin" ]; then
        echo "=== $name: NOT INSTALLED"; rc=1; return
    fi
    echo "=== $name $*"
    timeout -s INT "$secs" "$bin" "$@" 2>&1 | head -20
    local status=${PIPESTATUS[0]}
    # 124 = stopped by timeout, which is how streaming tools end.
    if [ "$status" -ne 0 ] && [ "$status" -ne 124 ]; then
        echo "=== $name FAILED (exit $status)"; rc=1
    fi
    echo
}

run_tool execsnoop -T      # short-lived processes being started
run_tool opensnoop         # files being opened, and failures
run_tool biolatency        # block device I/O latency histogram
run_tool runqlat           # time threads wait for a CPU
run_tool tcplife           # TCP sessions with duration and bytes
run_tool tcpretrans        # TCP retransmits
run_tool profile -F 49     # sampled CPU stacks, for flame graphs
exit $rc
