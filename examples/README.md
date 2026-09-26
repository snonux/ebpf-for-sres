# eBPF intro: runnable examples

Every example from the "eBPF for SREs" deck, as a script.

## Setup (Rocky Linux 9)

    sudo ./setup-rocky9.sh

Installs bpftrace, bcc-tools, bpftool, clang/llvm, libbpf-devel, gcc/make and
kernel-devel for the running kernel (bcc-tools compile against it).

## Run everything

    chmod +x *.sh *.bt
    sudo ./run-all.sh          # SECS=10 sudo ./run-all.sh for longer runs

Each tracing example runs for a few seconds while `workload.sh` generates file
I/O, then prints PASS/FAIL. Full output goes to `run-all.log`.

## The examples

| Slide | File | What it shows |
|---|---|---|
| Cover | `01-opens-per-process.bt` | openat() calls counted per process name |
| One-liner 1 | `02-opensnoop.bt` | Who opens which file, live |
| One-liner 2 | `03-syscalls-per-process.bt` | Syscalls per process, counted in a kernel map |
| One-liner 3 | `04-read-size-hist.bt` | Histogram of bytes returned by read() |
| One-liner 4 | `05-read-latency.bt` | read() latency histogram: enter/exit pairing per thread, like ior |
| One-liner 4 (variant) | `05b-vfs-read-latency-kprobe.bt` | Same with a kprobe on vfs_read (needs CONFIG_KPROBES) |
| libbpf in C | `libbpf/` | `make && sudo ./count_writes 10`, then `sudo bpftool map dump name counts` |
| Toolbox | `07-bcc-tools.sh` | execsnoop, opensnoop, biolatency, runqlat, tcplife, tcpretrans, profile |
| Next steps | `06-list-probes.sh` | List the syscall tracepoints you can hook |

Run any single one with `sudo ./02-opensnoop.bt` (or `sudo bpftrace 02-opensnoop.bt`)
and stop it with Ctrl-C; the counting and histogram scripts print their map on exit.

bpftrace older than 0.20 needs `args->filename` instead of `args.filename`;
`run-all.sh` detects this and rewrites the scripts on the fly.
