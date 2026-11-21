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
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

// Set from Go before loading (const volatile: read-only, known to the verifier).
const volatile u64 target_mntns = 0;   // mount namespace inode, 0 = any
const volatile u32 target_dev = 0;     // kernel dev_t of the filesystem at -path

enum io_op { IO_READ, IO_WRITE, IO_OPEN, IO_FSYNC, IO_CLOSE };

struct io_start {
    u64 ts;
    u32 op;
};

struct io_key {
    u32 pid;   // PID as seen inside the container
    u32 op;
};

struct io_stats {
    u64 count;
    u64 bytes;
    u64 errors;
    u64 lat_ns;
    u64 max_ns;
    char comm[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u32);              // thread id
    __type(value, struct io_start);
} starts SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, struct io_key);
    __type(value, struct io_stats);
} stats SEC(".maps");

static __always_inline bool in_target_container(struct task_struct *t)
{
    return !target_mntns || BPF_CORE_READ(t, nsproxy, mnt_ns, ns.inum) == target_mntns;
}

// fd -> struct file -> inode -> superblock -> s_dev
static __always_inline u32 fd_dev(struct task_struct *t, long fd)
{
    struct fdtable *fdt = BPF_CORE_READ(t, files, fdt);
    struct file **fds, *f = NULL;

    if (fd < 0 || fd >= BPF_CORE_READ(fdt, max_fds))
        return 0;
    fds = BPF_CORE_READ(fdt, fd);
    bpf_core_read(&f, sizeof(f), &fds[fd]);
    if (!f)
        return 0;
    return BPF_CORE_READ(f, f_inode, i_sb, s_dev);
}

// The PID in the innermost PID namespace, which is what `ps` in the pod shows.
static __always_inline u32 ns_pid(struct task_struct *t)
{
    struct pid *p = BPF_CORE_READ(t, group_leader, thread_pid);
    unsigned int level = BPF_CORE_READ(p, level);
    struct upid up = {};

    bpf_core_read(&up, sizeof(up), &p->numbers[level]);
    return up.nr;
}

static __always_inline int on_enter(long fd, u32 op)
{
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();

    if (!in_target_container(t))
        return 0;
    // For open we only know the file on return, when we have the new fd.
    if (op != IO_OPEN && fd_dev(t, fd) != target_dev)
        return 0;
    u32 tid = (u32)bpf_get_current_pid_tgid();
    struct io_start s = { .ts = bpf_ktime_get_ns(), .op = op };
    bpf_map_update_elem(&starts, &tid, &s, BPF_ANY);
    return 0;
}

static __always_inline int on_exit(long ret)
{
    u32 tid = (u32)bpf_get_current_pid_tgid();
    struct io_start *s = bpf_map_lookup_elem(&starts, &tid);
    if (!s)
        return 0;
    u64 delta = bpf_ktime_get_ns() - s->ts;
    u32 op = s->op;
    bpf_map_delete_elem(&starts, &tid);

    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    if (op == IO_OPEN && (ret < 0 || fd_dev(t, ret) != target_dev))
        return 0;   // failed opens cannot be tied to a filesystem

    struct io_key k = { .pid = ns_pid(t), .op = op };
    struct io_stats *st = bpf_map_lookup_elem(&stats, &k);
    if (!st) {
        struct io_stats zero = {};
        bpf_get_current_comm(&zero.comm, sizeof(zero.comm));
        bpf_map_update_elem(&stats, &k, &zero, BPF_NOEXIST);
        st = bpf_map_lookup_elem(&stats, &k);
        if (!st)
            return 0;
    }
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
