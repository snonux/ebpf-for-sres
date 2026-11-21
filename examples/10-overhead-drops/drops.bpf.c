//go:build ignore

// Kernel side of 10: one event per syscall into a small ring buffer, and a
// counter of the events that did not fit. BPF never waits for user space:
// when the buffer is full, bpf_ringbuf_reserve() fails and the event is lost.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct event {
    u32 pid;
    u32 cpu;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 16 * 1024);   // tiny on purpose (minimum is one page)
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);   // lock-free counter per CPU
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u64);
} dropped SEC(".maps");

SEC("tracepoint/raw_syscalls/sys_enter")
int on_syscall(void *ctx)
{
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        u32 zero = 0;
        u64 *n = bpf_map_lookup_elem(&dropped, &zero);
        if (n)
            (*n)++;   // per-CPU value: no atomic needed
        return 0;
    }
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->cpu = bpf_get_smp_processor_id();
    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
