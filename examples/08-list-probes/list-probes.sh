#!/bin/bash
# 08: where probes come from. Everything bpftrace -l shows is backed by files
# in tracefs and sysfs, which you can read without any BPF tool at all.
# Run: sudo ./list-probes.sh
set -uo pipefail
T=/sys/kernel/tracing
[ -d "$T/events" ] || T=/sys/kernel/debug/tracing

echo "== Tracepoints: $T/events/<group>/<name>"
echo "   $(ls "$T/events" | wc -l) groups, $(wc -l < "$T/available_events") tracepoints"
echo
echo "== The format file describes the arguments of one tracepoint:"
cat "$T/events/syscalls/sys_enter_openat/format"
echo
echo "== The same through bpftrace:"
bpftrace -lv 'tracepoint:syscalls:sys_enter_openat'
echo
echo "== Syscall tracepoints with 'open' in the name:"
bpftrace -l 'tracepoint:syscalls:*open*'
echo
echo "== kprobes: kernel functions you can hook ($T/available_filter_functions)"
if [ -r "$T/available_filter_functions" ] && head -1 "$T/available_filter_functions" >/dev/null 2>&1; then
    echo "   $(wc -l < "$T/available_filter_functions") functions, e.g.:"
    grep -E '^vfs_(read|write)\b' "$T/available_filter_functions"
else
    echo "   (not readable here)"
fi
echo
echo "== Kernel BTF, what CO-RE and bpftrace read struct layouts from:"
ls -l /sys/kernel/btf/vmlinux
echo
echo "== uprobes: functions in a user binary, from its ELF symbol table:"
bpftrace -l 'uprobe:/usr/bin/bash:*readline*' 2>/dev/null | head -5
bpftrace -l 'uprobe:libc:getaddrinfo' 2>/dev/null
