#!/bin/bash
# Installs what the examples need on Rocky Linux 9 (tested target: 9.9; also
# RHEL 9 and AlmaLinux 9).
#
#   sudo ./setup-rocky9.sh            bpftrace, bcc-tools, bpftool, clang/llvm, libbpf
#   sudo ./setup-rocky9.sh --go       plus Go, mage and what libbpfgo links against
#   sudo ./setup-rocky9.sh --all      everything
set -euo pipefail
want_go=0
for a in "$@"; do
    case $a in
        --go) want_go=1 ;;
        --all) want_go=1 ;;
        *) echo "unknown option $a"; exit 1 ;;
    esac
done
[ "$(id -u)" -eq 0 ] || { echo "run as root: sudo $0 $*"; exit 1; }

# libbpf-devel lives in CRB (CodeReady Builder), which is off by default.
dnf -y install dnf-plugins-core
dnf config-manager --set-enabled crb

kver=$(uname -r)
pkgs=(bpftrace bcc-tools bpftool clang llvm libbpf-devel gcc make
      elfutils-libelf-devel zlib-devel python3)
# bcc-tools compiles against the headers of the running kernel.
# If this kernel is older than the newest one in the repos, its kernel-devel may
# be gone: then "dnf -y update kernel && reboot" and run this script again.
if dnf -q list --available "kernel-devel-$kver" >/dev/null 2>&1 || rpm -q "kernel-devel-$kver" >/dev/null 2>&1; then
    pkgs+=("kernel-devel-$kver")
else
    echo "WARNING: kernel-devel-$kver is not available. bcc-tools needs it:"
    echo "         dnf -y update kernel && reboot, then run this script again."
fi
if [ "$want_go" -eq 1 ]; then
    # libbpfgo links libbpf statically, libelf, zlib and zstd dynamically.
    pkgs+=(golang git libzstd-devel)
fi
dnf -y install "${pkgs[@]}"

if [ "$want_go" -eq 1 ]; then
    GOBIN=/usr/local/bin go install github.com/magefile/mage@v1.15.0
fi

echo
echo "== Checks"
echo "kernel:   $kver"
[ -r /sys/kernel/btf/vmlinux ] && echo "BTF:      /sys/kernel/btf/vmlinux present (CO-RE works)" \
                               || echo "BTF:      MISSING, CO-RE programs will not load"
mountpoint -q /sys/kernel/tracing || mount -t tracefs tracefs /sys/kernel/tracing
echo "tracefs:  $(ls /sys/kernel/tracing/events | wc -l) tracepoint groups"
echo "bpftrace: $(bpftrace --version)"
echo "bpftool:  $(bpftool version | head -1)"
echo "libbpf:   $(rpm -q libbpf)"
[ "$want_go" -eq 1 ] && echo "go:       $(go version)   mage: $(mage -version | head -1)"
echo
echo "Next: sudo ./run-all.sh   (sudo GO=1 ./run-all.sh to include the Go versions)"
