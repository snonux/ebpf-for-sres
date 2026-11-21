# eBPF for SREs

An introduction to BPF for site reliability engineers and principal
engineers: what it is, why it is safe on production boxes, what it costs, how
CO-RE makes tools portable, how to write small tools in Go with libbpfgo, and
how to trace a pod in Kubernetes from a debug container, and how an LLM helps
with all of it. It closes with a demo of [ior](https://github.com/snonux/ior)
(I/O Riot NG) plus an LLM.

Every example runs on **Rocky Linux 9.9**.

## Contents

- `presentation/`: the deck (34 slides, about 45 minutes with three demos,
  for a 50-minute slot). See [presentation/README.md](presentation/README.md),
  [speaker notes and timing](presentation/speaker-notes.md) and the
  [demo plan](presentation/demo-plan.md).
- `examples/`: 13 examples, one directory each, as bpftrace and Go
  (libbpfgo) where it makes sense, with a test runner.
  See [examples/README.md](examples/README.md).
- `examples/13-k8s-store-iops/`: a static Go + BPF tool that measures IOPS on a
  pod's `/store` (EFS) volume, and the Kubernetes debug-container workflow to
  run it. See [its README](examples/13-k8s-store-iops/README.md).

## Quick start on Rocky Linux 9.9

```sh
cd examples
sudo ./setup-rocky9.sh --all      # enables CRB, installs bpftrace, bcc-tools, bpftool,
                                  # clang/llvm, libbpf-devel, Go, mage
sudo GO=1 ./run-all.sh            # runs every example and prints PASS/FAIL/SKIP
```

## Test status

`examples/results/sandbox-run.log` is the latest full run. It was made in an
Ubuntu 24.04 sandbox on a 6.18 kernel with bpftrace 0.20.2, Go 1.24 and
libbpfgo v0.9.2-libbpf-1.5.1, not on Rocky 9.9: no Rocky machine or image was
reachable from there. 21 of 24 runnable checks passed. The three failures are
environmental: that kernel has no kprobe support (example 06, bpftrace and Go)
and bcc-tools is not packaged there (example 09). Please run `sudo GO=1 ./run-all.sh` on a
Rocky 9.9 box before presenting.
