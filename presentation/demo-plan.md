# Demo plan (50 minutes in total)

The deck runs about 44 minutes including three demos (see the timing table in
`speaker-notes.md`), which leaves about 6 minutes for questions.

| When | What | Time |
|---|---|---|
| Slide 16, after the bpftrace examples | Demo 1: bpftrace, and the compiler at work | 2 min |
| Slides 26 to 28 | The featured Go example, storeiops, at medium depth (kernel side, user side) | 4 min |
| Slide 29 | Demo 2: the Kubernetes debug-container workflow, rehearsed with podman | 4 min |
| Slide 32, at the end | Demo 3: static ior in the debug container, then an LLM reads the trace and the app's source | 5 min |

All other Go examples are a flyover: slide 20 (example 11, the anatomy every
example shares) and slide 23 (a table of all of them). Open one in the editor
only if someone asks.

## Before the talk (on the Rocky Linux 9.9 demo box)

```sh
git clone https://github.com/snonux/ebpf-for-sres && cd ebpf-for-sres/examples
sudo ./setup-rocky9.sh --all
sudo GO=1 ./run-all.sh                   # everything should PASS; keep the log as a fallback
podman build -t ebpf-static -f Containerfile.static .
podman run --rm -v "$PWD:/src:z" -w /src/13-k8s-store-iops ebpf-static mage static
podman pull registry.access.redhat.com/ubi9/ubi-minimal cgr.dev/chainguard/busybox
```

Pull the images beforehand so the demo does not depend on the network. Use a
large terminal font, two panes side by side.

## Demo 1: bpftrace live (2 min)

```sh
cd examples
sudo ./01-opens-per-process/opens.bt              # 10 s, Ctrl-C: counts per process
sudo ./02-opensnoop/opensnoop.bt                 # live events, Ctrl-C
sudo bpftrace -d all ./01-opens-per-process/opens.bt | less   # parser, semantic pass, LLVM IR
```

The point of the last command: bpftrace compiles on the host every time
(slide "bpftrace is a compiler that runs on your host"). The Go examples that
follow do the same work without a compiler on the target.

Optional, if the audience asks about cost: `sudo ./10-overhead-drops/overhead.sh`
prints the nanoseconds per program run, and
`sudo BPFTRACE_PERF_RB_PAGES=1 ./10-overhead-drops/drops.bt > /dev/null` shows "Lost N events".

## Featured Go example: storeiops (4 min, slides 27 and 28)

Walk through the slides, then show in the editor:

1. `13-k8s-store-iops/storeiops.bpf.c`: the two globals, `on_enter` with the
   two filters, `fd_dev`, and the `ENTER`/`EXIT` list at the bottom.
2. `13-k8s-store-iops/main.go`: `target()` and the `bpfrun.Load` call with
   `InitGlobalVariable`.
3. `13-k8s-store-iops/magefile.go`: `mage static`.

## Demo 2: Kubernetes debug-container workflow (5 min)

```sh
cd examples/13-k8s-store-iops
sudo ./podman-demo.sh 15
```

Point out: `ps` in the debug container shows the app's processes; the app also
reads `/etc/os-release` in its loop, but that never shows up, because it is not
on `/store`; nothing from the host shows up either.

With a real cluster, do the four steps from slide 26 instead (see
`examples/13-k8s-store-iops/README.md`).

## Demo 3: ior + an LLM (5 min)

Prepare: build the static ior on Rocky 9 (`mage buildDocker` in the ior
repository), pick a service whose source you can show, and have a recorded
`store.csv` ready in case the live capture is too quiet.

```sh
kubectl cp ior <pod>:/tmp/ior -c ebpf-debug
# in the debug container:
/tmp/ior -pid <PID> -plain -duration 60 > /tmp/io.csv
grep ',/store/' /tmp/io.csv > /tmp/store.csv
kubectl cp <pod>:/tmp/store.csv . -c ebpf-debug
# then give store.csv and the app's source tree to the LLM:
#   "Here is 60 s of file I/O on /store and the app's source tree. Which code
#    paths cause the fsync calls, and how would you batch them?"
```

Check before the talk which PID ior expects when it runs in the pod's debug
container (the PID inside the pod, or the node PID). If it is the node PID,
use a node debug container (`kubectl debug node/<node> --profile=sysadmin`)
and the app's host PID instead.

## Fallbacks

* No network: everything above runs offline once the setup is done.
* A probe fails to attach: show `examples/results/` instead.
* Out of time: skip demo 1 and mention the one-liners are in the repository.
* Demo 3 capture too quiet: use the recorded `store.csv`; the LLM part works the same.
