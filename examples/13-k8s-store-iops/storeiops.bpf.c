//go:build ignore

// Kernel side of 13: file IOPS, throughput and latency per process and
// operation, only for files on one filesystem (the one mounted at /store, for
// example an EFS/NFS volume) and only for processes of one container.
//
// It uses stable syscall tracepoints. The fd argument is turned into the
// struct file it points to, and the file's filesystem (its superblock's s_dev)
// is compared with target_dev. The container is identified by its mount
// namespace. Every kernel struct access goes through BPF_CORE_READ, so the
// same object runs on Rocky 9's 5.14 kernel and on newer ones (CO-RE).
//
// This is the largest example, but it only combines what 01 to 12 introduced:
//   - the entry/exit pair with a start map, to measure latency (05)
//   - global variables as filters, set by user space before loading (new here)
//   - CO-RE reads of kernel structs (12), to answer two questions per syscall:
//     "is this process in the target container?" and "is this file descriptor
//     on the target filesystem?"
//   - a hash map of totals that user space reads and clears every second (01)
//
// Flow for one syscall, e.g. a write(fd, buf, n) by the app:
//   sys_enter_write -> on_enter(): right container? right filesystem?
//                      if yes: starts[thread] = { now, IO_WRITE }
//   sys_exit_write  -> on_exit():  latency = now - starts[thread].ts
//                      stats[{pid, IO_WRITE}]: count++, bytes += ret, ...
//
// Everything else on the node leaves on_enter() after one or two comparisons,
// which keeps the overhead low even though the probes fire for every process.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

// Global variables: the tool's settings.
// Set from Go before loading (const volatile: read-only, known to the verifier).
// main.go writes the real values into the object with InitGlobalVariable()
// before it is loaded; after loading they cannot change. "const" lets the
// verifier treat them as constants, and "volatile" stops clang from baking the
// initial 0 into the code at compile time.
const volatile u64 target_mntns = 0;   // mount namespace inode, 0 = any
const volatile u32 target_dev = 0;     // kernel dev_t of the filesystem at -path

// The kinds of operation we tell apart. Several syscalls map to one kind:
// read, pread64 and readv are all IO_READ (see the ENTER/EXIT list at the end).
enum io_op { IO_READ, IO_WRITE, IO_OPEN, IO_FSYNC, IO_CLOSE };

// What on_enter() leaves for on_exit(): when the syscall started and which
// kind it is. One entry per thread that is currently inside a traced syscall.
struct io_start {
    u64 ts;
    u32 op;
};

// Key of the result map: statistics are kept per process and per operation.
struct io_key {
    u32 pid;   // PID as seen inside the container
    u32 op;
};

// Value of the result map: running totals since user space last cleared the
// entry. main.go turns them into IOPS, MiB/s and average latency.
struct io_stats {
    u64 count;      // number of calls
    u64 bytes;      // bytes read or written (0 for open, fsync, close)
    u64 errors;     // calls that returned an error
    u64 lat_ns;     // sum of all latencies; divided by count gives the average
    u64 max_ns;     // slowest single call
    char comm[16];  // process name
};

// In-flight syscalls: thread ID -> start time and operation. Internal to the
// BPF side; user space never reads it.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u32);              // thread id
    __type(value, struct io_start);
} starts SEC(".maps");

// The results: (PID, operation) -> totals. main.go reads and deletes every
// entry once per interval, so each report covers exactly one interval.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, struct io_key);
    __type(value, struct io_stats);
} stats SEC(".maps");

// Filter 1: is the current process in the container we were asked to trace?
// The kernel has no notion of a "container"; a container is a set of
// namespaces. All processes of one container share one mount namespace, and
// every namespace has a unique inode number (ls -l /proc/<pid>/ns/mnt shows
// it). So: task -> nsproxy (its namespaces) -> mnt_ns -> ns.inum, compared
// with the number main.go got from /proc/<pid>/ns/mnt. target_mntns == 0
// switches the filter off.
static __always_inline bool in_target_container(struct task_struct *t)
{
    return !target_mntns || BPF_CORE_READ(t, nsproxy, mnt_ns, ns.inum) == target_mntns;
}

// Filter 2 helper: which filesystem is file descriptor fd on?
// fd -> struct file -> inode -> superblock -> s_dev
// A file descriptor is just an index into the process's table of open files:
//   task->files->fdt->fd[fd]   is the struct file of that descriptor
//   file->f_inode->i_sb        is the superblock, the kernel's object for one
//                              mounted filesystem
//   superblock->s_dev          is that filesystem's device number
// Every mounted filesystem, including an NFS/EFS mount, has its own s_dev, so
// comparing it with target_dev tells us whether the file lives under /store.
// Returns 0 (matches nothing) if fd is not a valid open descriptor.
static __always_inline u32 fd_dev(struct task_struct *t, long fd)
{
    struct fdtable *fdt = BPF_CORE_READ(t, files, fdt);
    struct file **fds, *f = NULL;

    // Bounds check before indexing the table, as the kernel itself does.
    if (fd < 0 || fd >= BPF_CORE_READ(fdt, max_fds))
        return 0;
    fds = BPF_CORE_READ(fdt, fd);
    // Read one pointer, the fd-th entry of the array, from kernel memory.
    bpf_core_read(&f, sizeof(f), &fds[fd]);
    if (!f)
        return 0;
    return BPF_CORE_READ(f, f_inode, i_sb, s_dev);
}

// The PID in the innermost PID namespace, which is what `ps` in the pod shows.
// A process in a container has several PIDs: one per nested PID namespace
// (e.g. 48213 on the node, 1 in the pod). bpf_get_current_pid_tgid() returns
// the node's view. The kernel keeps all of them in struct pid, in the array
// numbers[], indexed by nesting level; the last one (index "level") is the
// innermost, and that is the one the pod's owner recognises.
static __always_inline u32 ns_pid(struct task_struct *t)
{
    struct pid *p = BPF_CORE_READ(t, group_leader, thread_pid);
    unsigned int level = BPF_CORE_READ(p, level);
    struct upid up = {};

    bpf_core_read(&up, sizeof(up), &p->numbers[level]);
    return up.nr;
}

// Common entry handler for all traced syscalls. fd is the syscall's first
// argument (the file descriptor for everything except openat), op its kind.
static __always_inline int on_enter(long fd, u32 op)
{
    // Helper: pointer to the task_struct of the process running right now.
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();

    if (!in_target_container(t))
        return 0;   // some other container or the host: not interested
    // For open we only know the file on return, when we have the new fd.
    if (op != IO_OPEN && fd_dev(t, fd) != target_dev)
        return 0;
    // Both filters passed: remember when this thread entered the syscall.
    u32 tid = (u32)bpf_get_current_pid_tgid();   // lower 32 bits: thread ID
    struct io_start s = { .ts = bpf_ktime_get_ns(), .op = op };
    bpf_map_update_elem(&starts, &tid, &s, BPF_ANY);
    return 0;
}

// Common exit handler. ret is the syscall's return value: bytes for read and
// write, the new fd for openat, 0 for fsync and close, negative on error.
static __always_inline int on_exit(long ret)
{
    u32 tid = (u32)bpf_get_current_pid_tgid();
    struct io_start *s = bpf_map_lookup_elem(&starts, &tid);
    if (!s)
        return 0;   // on_enter() filtered this call out, or we attached mid-call
    u64 delta = bpf_ktime_get_ns() - s->ts;
    u32 op = s->op;   // copy before deleting: s points into the map entry
    bpf_map_delete_elem(&starts, &tid);

    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    if (op == IO_OPEN && (ret < 0 || fd_dev(t, ret) != target_dev))
        return 0;   // failed opens cannot be tied to a filesystem

    // Find the totals for this (PID, operation), creating them on first use.
    struct io_key k = { .pid = ns_pid(t), .op = op };
    struct io_stats *st = bpf_map_lookup_elem(&stats, &k);
    if (!st) {
        // Insert a zeroed entry (BPF_NOEXIST: do not overwrite one that
        // another CPU just created), then look it up again to get a pointer
        // into the map that we can update in place.
        struct io_stats zero = {};
        bpf_get_current_comm(&zero.comm, sizeof(zero.comm));
        bpf_map_update_elem(&stats, &k, &zero, BPF_NOEXIST);
        st = bpf_map_lookup_elem(&stats, &k);
        if (!st)
            return 0;
    }
    // Atomic adds: other threads of the app may update the same entry on
    // other CPUs at the same time.
    __sync_fetch_and_add(&st->count, 1);
    __sync_fetch_and_add(&st->lat_ns, delta);
    if (ret < 0)
        __sync_fetch_and_add(&st->errors, 1);
    else if (op == IO_READ || op == IO_WRITE)
        __sync_fetch_and_add(&st->bytes, ret);
    if (delta > st->max_ns)
        st->max_ns = delta;   // racy but good enough for a maximum
    return 0;
}

// One tracepoint program per syscall. Writing each out by hand would be 20
// near-identical functions, so two macros generate them:
//   ENTER(read, IO_READ)  becomes
//     SEC("tracepoint/syscalls/sys_enter_read")
//     int enter_read(struct syscall_trace_enter *ctx) { return on_enter(ctx->args[0], IO_READ); }
//   EXIT(read)  becomes
//     SEC("tracepoint/syscalls/sys_exit_read")
//     int exit_read(struct syscall_trace_exit *ctx) { return on_exit(ctx->ret); }
// ctx->args[0] is the first syscall argument: the fd for all of these except
// openat, where it is the directory fd and on_enter() ignores it.
#define ENTER(sc, op)                                             \
    SEC("tracepoint/syscalls/sys_enter_" #sc)                     \
    int enter_##sc(struct syscall_trace_enter *ctx)           \
    {                                                             \
        return on_enter(ctx->args[0], op);                        \
    }
#define EXIT(sc)                                                  \
    SEC("tracepoint/syscalls/sys_exit_" #sc)                      \
    int exit_##sc(struct syscall_trace_exit *ctx)             \
    {                                                             \
        return on_exit(ctx->ret);                                 \
    }

// The traced syscalls. To add one, add a line here; libbpf attaches every
// program it finds in the object.
ENTER(read, IO_READ)       EXIT(read)
ENTER(pread64, IO_READ)    EXIT(pread64)
ENTER(readv, IO_READ)      EXIT(readv)
ENTER(write, IO_WRITE)     EXIT(write)
ENTER(pwrite64, IO_WRITE)  EXIT(pwrite64)
ENTER(writev, IO_WRITE)    EXIT(writev)
ENTER(openat, IO_OPEN)     EXIT(openat)
ENTER(fsync, IO_FSYNC)     EXIT(fsync)
ENTER(fdatasync, IO_FSYNC) EXIT(fdatasync)
// On NFS (EFS) close() flushes dirty pages to the server: it is often the slow one.
ENTER(close, IO_CLOSE)     EXIT(close)

// Why struct syscall_trace_enter/exit and not trace_event_raw_sys_enter/exit:
// RHEL 9 kernels (and so Rocky 9) widen the trace_event_raw_* types by 8 bytes,
// which shifts args/ret and makes the verifier reject the program (EACCES).
// The syscall_trace_* structs match what the kernel really passes. Same fix
// as ior and bcc (github.com/iovisor/bcc/pull/4920).
char LICENSE[] SEC("license") = "GPL";
