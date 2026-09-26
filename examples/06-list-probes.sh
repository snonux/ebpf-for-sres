#!/bin/bash
# Next steps slide: list the syscall tracepoints you can hook that mention "open".
set -euo pipefail
sudo bpftrace -l 'tracepoint:syscalls:*open*'
echo
echo "Arguments of sys_enter_openat:"
sudo bpftrace -lv 'tracepoint:syscalls:sys_enter_openat'
