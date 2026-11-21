//go:build ignore

// Kernel side of 12: CO-RE in practice. BPF_CORE_READ(task, real_parent, tgid)
// compiles to a field access plus a relocation record. When libbpf loads the
// object it looks up struct task_struct in the running kernel's BTF
// (/sys/kernel/btf/vmlinux) and patches in the real offsets. One binary, built
// once, then runs on Rocky 9's 5.14 kernel and on a 6.x kernel alike.
//
// What it does: report every program that is started (exec), with its PID,
// parent PID, user and path. Short-lived processes that top never shows
// appear here.
//
// Why CO-RE matters here: the earlier examples only used helpers and syscall
// arguments, which look the same on every kernel. This one reads fields of
// kernel structs (task_struct, linux_binprm), and their byte offsets differ
// from kernel to kernel. On the kernel this was written on, real_parent sits
// at byte 1280 of task_struct; on Rocky 9.9 it sits at byte 2760. Without
// CO-RE the offset of the build machine would be compiled in and the program
// would read the wrong memory elsewhere.
//
// See the offsets of your kernel:
//   bpftool btf dump file /sys/kernel/btf/vmlinux | grep -A260 "STRUCT 'task_struct'"
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>   // BPF_CORE_READ()
#include <bpf/bpf_tracing.h>     // BPF_PROG()

// One record per exec, sent through the ring buffer. main.go has the same
// struct in Go.
struct event {
    u32 pid;
    u32 ppid;            // parent process ID: who started it
    u32 uid;             // user ID it runs as
    char comm[16];       // process name
    char filename[128];  // path of the executed file
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);   // bytes
} events SEC(".maps");

// tp_btf: the same sched_process_exec tracepoint, but with typed, BTF-described
// arguments instead of a raw record, so the filename comes from struct
// linux_binprm through CO-RE too. Needs no tracefs (handy in containers).
SEC("tp_btf/sched_process_exec")
// BPF_PROG() unpacks the tracepoint's arguments into C parameters:
//   task: the process that just called exec (struct task_struct is the
//         kernel's per-process bookkeeping: PIDs, parent, credentials, files)
//   old_pid: its PID before the exec (unused)
//   bprm: the kernel's description of the binary being loaded
int BPF_PROG(handle_exec, struct task_struct *task, pid_t old_pid, struct linux_binprm *bprm)
{
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;   // ring buffer full: drop this event
    e->pid = bpf_get_current_pid_tgid() >> 32;
    // In plain C this would be task->real_parent->tgid: follow the pointer to
    // the parent's task_struct and read its process ID. BPF_CORE_READ does the
    // same in a way that is safe (each step is a checked read of kernel
    // memory) and portable (each field offset is looked up by name in the
    // running kernel's BTF when the program is loaded).
    e->ppid = BPF_CORE_READ(task, real_parent, tgid);   // relocated at load time
    // Helper returns gid in the upper and uid in the lower 32 bits.
    e->uid = (u32)bpf_get_current_uid_gid();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    // bprm->filename is a pointer to a string in KERNEL memory, so it is
    // copied with the _kernel_ variant of the read helper (02 and 07 read
    // user memory and use the _user_ variant).
    bpf_probe_read_kernel_str(&e->filename, sizeof(e->filename), BPF_CORE_READ(bprm, filename));
    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
