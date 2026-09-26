#!/bin/bash
# Installs everything the examples need on Rocky Linux 9 (also RHEL 9, Alma 9).
set -euo pipefail
sudo dnf -y install bpftrace bcc-tools bpftool clang llvm libbpf-devel \
    gcc make elfutils-libelf-devel zlib-devel \
    "kernel-devel-$(uname -r)"   # bcc-tools compile against the running kernel headers
bpftrace --version
bpftool version | head -1
