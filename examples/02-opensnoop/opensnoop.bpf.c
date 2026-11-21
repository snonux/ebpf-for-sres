//go:build ignore

// Kernel side of 02: stream one event per openat() to user space through a
// ring buffer. Same as opensnoop.bt, but every event leaves the kernel.
//
// New compared with 01 (read that file first for the basics):
//   - a ring buffer instead of a hash map: one record per event, not a total
//   - reading the syscall's arguments from ctx
//   - copying a string out of the traced process's memory
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

// The record sent to user space for every openat(). main.go declares the same
// struct in Go, field by field in the same order and with the same sizes:
// the two sides share bytes, not types, so the layouts must match exactly.
struct event {
    u32 pid;
    char comm[16];        // process name
    char filename[256];   // path as the process passed it, cut off after 255 bytes
};

// A ring buffer: a queue of variable-sized records that the kernel writes and
// user space reads. It has no key or value type, only a size in bytes, which
// must be a power of two and a multiple of the page size. All CPUs share this
// one buffer (the older "perf buffer" needs one per CPU).
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);   // bytes, shared by all CPUs
} events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_openat")
// This time ctx has a type: the record every syscall-entry tracepoint gets.
// ctx->nr is the syscall number and ctx->args[0..5] are its arguments, here
// openat(int dirfd, const char *pathname, int flags, mode_t mode).
int trace_openat(struct syscall_trace_enter *ctx)
{
    // Reserve room for one record directly inside the ring buffer, so the
    // event is built in place and never copied.
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;   // buffer full: this event is dropped
    // The helper returns two IDs in one u64: the upper 32 bits are the process
    // ID (what ps shows as PID, the kernel calls it tgid), the lower 32 bits
    // are the thread ID.
    e->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    // args[1] is the filename pointer in user memory: copy it safely.
    // A BPF program may not dereference a user-space pointer directly: the
    // page could be missing or the pointer garbage. This helper copies up to
    // sizeof(filename) bytes, always NUL-terminates, and fails cleanly instead
    // of faulting.
    bpf_probe_read_user_str(&e->filename, sizeof(e->filename), (void *)ctx->args[1]);
    // Hand the record over to user space. After submit, e must not be used.
    // A reserved record must always be submitted or discarded; the verifier
    // checks that on every path.
    bpf_ringbuf_submit(e, 0);
    return 0;
}

// Why struct syscall_trace_enter/exit and not trace_event_raw_sys_enter/exit:
// RHEL 9 kernels (and so Rocky 9) widen the trace_event_raw_* types by 8 bytes,
// which shifts args/ret and makes the verifier reject the program (EACCES).
// The syscall_trace_* structs match what the kernel really passes. Same fix
// as ior and bcc (github.com/iovisor/bcc/pull/4920).
char LICENSE[] SEC("license") = "GPL";
