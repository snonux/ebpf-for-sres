# 13: Trace a Kubernetes pod's /store IOPS from a debug container

`storeiops` answers "how many IOPS, how much throughput and what latency does
this pod see on its `/store` volume?" for a running pod, without restarting it,
without a shell in the app image, and without installing anything on the node.
The typical case is an EFS (NFS) volume mounted at `/store` that feels slow.

```
16:02:11     PID COMM             OP         IOPS     MiB/s    AVG_us    MAX_us   ERR
               - java             write      1840      7.19      21.4    2210.9     0
               - java             fsync        92      0.00    8410.2   41022.7     0
               - java             close        88      0.00    5120.6   30219.0     0
               - java             read        310      1.21     812.3    9120.4     0
         total 2330 IOPS
```

## How it works

```
 node kernel ─────────────────────────────────────────────────────────────
   syscall tracepoints (read/write/pread/pwrite/readv/writev/openat/
   fsync/fdatasync/close) → BPF filter:
     • current task's mount namespace == app container's?   (mntns inode)
     • fd → struct file → inode → superblock: is it the /store filesystem? (s_dev)
   → per (PID, op) counters in a hash map: count, bytes, errors, latency
 ─────────────────────────────────────────────────────────────────────────
 pod
   app container            debug container (ephemeral, privileged, root)
   PID 1: java ...  ◄─────  shares app's PID namespace (--target=app)
   /store (EFS)             /tmp/storeiops -pid 1 -path /store
                            reads /proc/1/ns/mnt and stats /proc/1/root/store,
                            loads the BPF object, prints the map every second
```

* The BPF program runs in the node's kernel and sees **every** process on the
  node. The mount namespace filter keeps it to the app container, the device
  filter keeps it to `/store`. Nothing else ever reaches the map.
* `storeiops` is **one static binary** with the BPF object embedded. CO-RE
  (`BPF_CORE_READ`) fixes up struct offsets for whatever kernel the node runs,
  so the same file works on Rocky 9's 5.14 kernel and on newer ones.
* When the binary exits, the kernel detaches and frees the programs and maps.

## Build the static binary

On Rocky Linux 9 (the libraries for a static build are not all packaged, the
container builds them):

```sh
cd examples
podman build -t ebpf-static -f Containerfile.static .
podman run --rm -v "$PWD:/src:z" -w /src/13-k8s-store-iops ebpf-static mage static
file 13-k8s-store-iops/storeiops    # ... statically linked
```

**arm64 nodes** (Graviton and similar) need an arm64 binary. Simplest: run the
same two commands on an arm64 machine. To cross-build on an x86_64 box, register
qemu-user-static for aarch64 and add `--platform linux/arm64` to both `podman`
commands. Under emulation `/sys/kernel/btf/vmlinux` is still the x86_64
kernel's, so first put an arm64 `vmlinux.h` into `examples/.build/` (on any
arm64 node: `bpftool btf dump file /sys/kernel/btf/vmlinux format c`).

For a quick dynamically linked build on the same host: `mage` (see the
examples README for `setup-rocky9.sh --go`).

## The workflow

Prerequisites: Kubernetes 1.25 or newer (ephemeral containers), kubectl 1.27
or newer (`--profile=sysadmin`), a namespace whose Pod Security level allows
privileged containers, and node kernels with BTF (`/sys/kernel/btf/vmlinux`:
Rocky/RHEL 9, Amazon Linux 2023, Bottlerocket, Ubuntu 20.10+).

**1. Find the pod, the container and the volume.**

```sh
kubectl get pod app-7d9f -o jsonpath='{.spec.containers[*].name}'      # app
kubectl get pod app-7d9f -o jsonpath='{.spec.containers[0].volumeMounts}'  # .../store
```

**2. Attach a debug container in root context.** `--target` puts it into the
app container's PID namespace, `--profile=sysadmin` makes it privileged (root,
all capabilities), which loading BPF programs needs. The app image can be
distroless (a Chainguard image, for example): the tools come with the debug image.

```sh
kubectl debug -it pod/app-7d9f --target=app --profile=sysadmin \
    --image=docker.io/library/busybox:latest --container=ebpf-debug -- sh
```

The debug image must run as **root**. `--profile=sysadmin` makes the container
privileged but keeps the image's user, and a non-root user has no capabilities
even in a privileged container: `ls /proc/1/root/store` says "Permission
denied" and loading BPF fails. `cgr.dev/chainguard/busybox` runs as `nonroot`,
so it needs `--custom` to override the user:

```sh
echo '{"securityContext":{"runAsUser":0}}' > root.json
kubectl debug -it pod/app-7d9f --target=app --profile=sysadmin --custom=root.json \
    --image=cgr.dev/chainguard/busybox:latest --container=ebpf-debug -- sh
```

**3. Upload the binary** (from a second terminal). `kubectl cp` needs `tar` in
the debug image, busybox has it. Without tar, stream it through `kubectl exec`.

```sh
kubectl cp 13-k8s-store-iops/storeiops app-7d9f:/tmp/storeiops -c ebpf-debug
# or: kubectl exec -i app-7d9f -c ebpf-debug -- sh -c 'cat > /tmp/storeiops; chmod +x /tmp/storeiops' < storeiops
```

**4. Find the app's PID and check that you see its /store.** In the debug
shell, `ps` lists the app's processes. The app's root file system is at
`/proc/<pid>/root`.

```sh
ps                              # PID 1 is usually the app
ls /proc/1/root/store           # the app's /store, seen from the debug container
```

**5. Trace.**

```sh
/tmp/storeiops -pid 1 -path /store -bycomm      # per process name and operation
/tmp/storeiops -pid 1 -path /store -interval 5s # per PID, 5 second buckets
```

**6. Clean up.** Ctrl-C and `exit`. The BPF programs go away with the process.
The ephemeral container stays in the pod spec in state Terminated until the
pod is replaced: that is how Kubernetes works, there is nothing to delete.

### Rehearse without a cluster

`sudo ./podman-demo.sh` runs the same workflow with podman on one Rocky 9 box:
an app container writing to a `/store` tmpfs, a privileged debug container in
its PID namespace, `podman cp` instead of `kubectl cp`.

## Gotchas

* **No tracefs in the container.** libbpf looks up tracepoint IDs in
  `/sys/kernel/tracing`, which a container's fresh `/sys` does not have mounted.
  `storeiops` mounts it when it is missing (that needs the privileged profile).
* **Pod Security Admission** rejects privileged ephemeral containers in
  `baseline` and `restricted` namespaces. Alternative with node access:
  `kubectl debug node/<node> -it --profile=sysadmin --image=...` gives a
  container in the host PID namespace. Find the app's host PID (for example
  with `crictl inspect`) and run `storeiops -pid <host pid> -path /store`.
* **Not a mount point.** If `/store` is just a directory on the container's
  root file system, the device filter matches the whole root file system;
  storeiops prints a note when that happens.
* **What it does not see:** I/O through `mmap`, `io_uring`, `sendfile` and
  `splice`, and metadata calls (`stat`, `getdents`), which also cost round
  trips on NFS. Each is one more tracepoint pair in `storeiops.bpf.c`.
* **Page cache.** Reads served from the page cache are fast and never reach
  EFS. For NFS, dirty data is flushed on `close()` and `fsync()`, so the
  latency shows up there and not on `write()`.
* **Kernel lockdown** in `confidentiality` mode forbids reading kernel memory
  from BPF. The default `integrity` mode (Secure Boot on RHEL) is fine.
