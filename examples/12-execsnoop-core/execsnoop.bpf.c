//go:build ignore

// Kernel side of 12: CO-RE in practice. BPF_CORE_READ(task, real_parent, tgid)
// compiles to a field access plus a relocation record. When libbpf loads the
// object it looks up struct task_struct in the running kernel's BTF
// (/sys/kernel/btf/vmlinux) and patches in the real offsets. One binary, built
// once, then runs on Rocky 9's 5.14 kernel and on a 6.x kernel alike.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

struct event {
    u32 pid;
    u32 ppid;
    u32 uid;
    char comm[16];
    char filename[128];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

// tp_btf: the same sched_process_exec tracepoint, but with typed, BTF-described
// arguments instead of a raw record, so the filename comes from struct
// linux_binprm through CO-RE too. Needs no tracefs (handy in containers).
SEC("tp_btf/sched_process_exec")
int BPF_PROG(handle_exec, struct task_struct *task, pid_t old_pid, struct linux_binprm *bprm)
{
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->ppid = BPF_CORE_READ(task, real_parent, tgid);   // relocated at load time
    e->uid = (u32)bpf_get_current_uid_gid();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_probe_read_kernel_str(&e->filename, sizeof(e->filename), BPF_CORE_READ(bprm, filename));
    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
