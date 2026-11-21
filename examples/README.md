# eBPF for SREs: runnable examples

Every example from the deck, each in its own directory and, where it makes
sense, in two flavours of the same idea:

* `*.bt`: a bpftrace script, the quickest way to ask a question.
* `main.go` + `*.bpf.c` + `magefile.go`: a small Go program using
  [libbpfgo](https://github.com/aquasecurity/libbpfgo). The BPF C file is the
  kernel side, `main.go` loads it (embedded in the binary), attaches it and
  reads the results. `mage` builds it, `sudo -E mage test` tests it.

Target platform: **Rocky Linux 9.9** (kernel 5.14 with RHEL's BPF backports),
also RHEL 9 and AlmaLinux 9.

## Setup on Rocky Linux 9.9

```sh
sudo ./setup-rocky9.sh          # bpftrace, bcc-tools, bpftool, clang/llvm, libbpf-devel
sudo ./setup-rocky9.sh --all    # plus Go and mage (for the Go versions)
```

What it does, if you prefer to type it yourself:

```sh
sudo dnf -y install dnf-plugins-core
sudo dnf config-manager --set-enabled crb          # libbpf-devel is in CRB
sudo dnf -y install bpftrace bcc-tools bpftool clang llvm libbpf-devel gcc make \
    elfutils-libelf-devel zlib-devel python3 "kernel-devel-$(uname -r)"
# Go versions:
sudo dnf -y install golang git libzstd-devel
sudo GOBIN=/usr/local/bin go install github.com/magefile/mage@v1.15.0
```

Notes for Rocky 9:

* `kernel-devel-$(uname -r)` (needed by bcc-tools, not by bpftrace or
  the Go examples) is only in the repos for current kernels. If dnf cannot find
  it, `sudo dnf -y update kernel && sudo reboot` first.
* The kernel has BTF (`/sys/kernel/btf/vmlinux`), so bpftrace struct access and
  CO-RE work out of the box.
* bcc-tools live in `/usr/share/bcc/tools`, not in `$PATH`.
* RHEL 9 kernels make the BTF type `trace_event_raw_sys_enter`/`_exit` 8 bytes
  wider than what a syscall tracepoint program really gets, so programs using
  it are rejected by the verifier (EACCES). The examples use
  `struct syscall_trace_enter`/`_exit` instead, like ior and bcc.
* The first `mage` run clones libbpfgo (pinned to `v0.9.2-libbpf-1.5.1`, the
  same as [ior](https://github.com/snonux/ior)) into `.build/` and builds a
  static libbpf from it. It needs access to github.com and proxy.golang.org.

## Run everything

```sh
sudo ./run-all.sh               # bpftrace and shell examples
sudo GO=1 ./run-all.sh          # also builds and tests every Go version
```

Each tracing example runs for a few seconds while `workload.sh` generates file
I/O and DNS lookups, then prints PASS, FAIL or SKIP. Full output goes to
`run-all.log`. `results/` has the logs of earlier runs.

Run a single one:

```sh
cd 05-read-latency
sudo ./readlat.bt                 # bpftrace, Ctrl-C prints the histogram
mage && sudo ./readlat            # Go: build, then run (Ctrl-C or -duration 5s)
```

## The examples

| Dir | bt | Go | What it shows | Hook |
|---|:-:|:-:|---|---|
| `01-opens-per-process` | ✓ | ✓ | openat() calls counted per process name | tracepoint |
| `02-opensnoop` | ✓ | ✓ | Who opens which file, live; Go streams events through a ring buffer | tracepoint |
| `03-syscalls-per-process` | ✓ | ✓ | All syscalls per process, counted in a kernel map | tracepoint |
| `04-read-size-hist` | ✓ | ✓ | Histogram of bytes returned by read() | tracepoint |
| `05-read-latency` | ✓ | ✓ | read() latency: enter/exit pairing per thread, like ior | tracepoint |
| `06-vfs-read-latency-kprobe` | ✓ | ✓ | The same on the kernel function vfs_read() | kprobe |
| `07-dns-latency-uprobe` | ✓ | ✓ | DNS lookup latency of any program, from libc's getaddrinfo() | uprobe |
| `08-list-probes` | sh | | Where probes come from: tracefs, format files, BTF, ELF symbols | |
| `09-bcc-tools` | sh | | Ready-made tools: execsnoop, opensnoop, biolatency, runqlat, ... | |
| `10-overhead-drops` | ✓ | ✓ | Cost per program run (`overhead.sh`), and dropped events when user space is too slow | tracepoint |
| `11-count-writes` | | ✓ | write() calls per PID: one BPF object, loaded by plain C (`make`) and by Go (`mage`) | tracepoint |
| `12-execsnoop-core` | ✓ | ✓ | Every exec with its parent PID, read from task_struct with CO-RE | tracepoint + CO-RE |
| `13-k8s-store-iops` | | ✓ | IOPS, MiB/s and latency on a pod's /store (EFS) from a Kubernetes debug container. Static binary. [README](13-k8s-store-iops/README.md) | tracepoint + CO-RE |

## How the Go examples are built

```
foo.bpf.c ──clang -target bpf──► foo.bpf.o ──go:embed──► main.go ──go build──► ./foo
   ▲                                                        │
   vmlinux.h (bpftool btf dump), bpf_helpers.h (libbpf)     libbpfgo → static libbpf.a
```

* `internal/magebpf`: the shared mage steps (libbpf, vmlinux.h, clang, go build,
  static build, test). Each `magefile.go` is a few lines that call it.
* `internal/bpfrun`: the shared runtime bits (load and attach, wait for Ctrl-C
  or `-duration`, print a histogram). Each `main.go` stays slide-sized.
* `mage static` builds a fully static binary. Rocky 9 does not package every
  static library that needs, so use the container:
  `podman build -t ebpf-static -f Containerfile.static .`, see
  [13-k8s-store-iops/README.md](13-k8s-store-iops/README.md).

bpftrace older than 0.20 needs `args->filename` instead of `args.filename`;
`run-all.sh` detects this and rewrites the scripts on the fly.
