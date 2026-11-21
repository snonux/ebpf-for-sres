# eBPF for SREs

An introduction to BPF for site reliability engineers and principal
engineers: what it is, why it is safe on production boxes, what it costs, how
CO-RE makes tools portable, how to write small tools in Go with libbpfgo, and
how to trace a pod in Kubernetes from a debug container, and how an LLM helps
with all of it. It closes with a demo of [ior](https://github.com/snonux/ior)
(I/O Riot NG) plus an LLM.

Every example runs on **Rocky Linux 9.9**.

## Contents

- `presentation/`: the deck (33 slides, about 44 minutes with three demos,
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

Tested 2026-11-21 on **Rocky Linux 9.9** (GenericCloud image, kernel
5.14.0-741.22.1.el9_9.x86_64, bpftrace 0.26.0, bcc-tools, Go 1.27.3, libbpf
1.5.0) in a qemu VM: `sudo ./setup-rocky9.sh --all && sudo GO=1 SECS=40
./run-all.sh` gives **24 passed, 0 failed**, including the kprobe example 06
and bcc-tools (09). Full log: [`examples/results/rocky-9.9-run.log`](examples/results/rocky-9.9-run.log).
The VM ran without KVM (software emulation), hence `SECS=40`: bpftrace needs
longer than 5 s to compile there. On real hardware the default is enough.

Also tested:

* `Containerfile.static` builds on Rocky 9 for amd64 and arm64, and
  `mage static` produces a static storeiops for both.
* `podman-demo.sh` with the static amd64 binary on the Rocky 9.9 VM.
* The Kubernetes workflow from `examples/13-k8s-store-iops/README.md` with the
  static **arm64** binary: k3s on Amazon Linux 2023 arm64 (kernel 6.1, the EKS
  node OS), app pod with an NFS 4.2 volume on `/store`, `kubectl debug
  --target --profile=sysadmin`, `kubectl cp`, trace. Also the
  `kubectl debug node/...` variant. The arm64 VM was emulated too, so the
  latency numbers mean nothing; the counts and the filtering were correct.
