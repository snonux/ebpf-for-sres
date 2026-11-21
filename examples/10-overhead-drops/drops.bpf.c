//go:build ignore

// Kernel side of 10: one event per syscall into a small ring buffer, and a
// counter of the events that did not fit. BPF never waits for user space:
// when the buffer is full, bpf_ringbuf_reserve() fails and the event is lost.
//
// This example is built to FAIL on purpose, so you can see what a lost event
// looks like: the hottest tracepoint on the system writes into the smallest
// possible buffer, and main.go can be told to read slowly (-slow). The lesson
// for real tools: the traced application is never slowed down by a slow
// reader, your data just gets holes. So count the drops and report them.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

// A deliberately small record: 8 bytes per syscall.
struct event {
    u32 pid;
    u32 cpu;   // which CPU the syscall ran on
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 16 * 1024);   // tiny on purpose (minimum is one page)
} events SEC(".maps");

// Where the drops are counted. A PERCPU_ARRAY has one separate copy of each
// value per CPU: a program only ever touches the copy of the CPU it runs on,
// so there is no locking and no cache line bouncing between CPUs. User space
// gets all the copies in one lookup and adds them up (see main.go). This is
// the right map type for counters on very hot paths.
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);   // lock-free counter per CPU
    __uint(max_entries, 1);                    // a single counter, at index 0
    __type(key, u32);
    __type(value, u64);
} dropped SEC(".maps");

// Fires for every syscall of every process (see 03).
SEC("tracepoint/raw_syscalls/sys_enter")
int on_syscall(void *ctx)
{
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        // No room: user space has not caught up. The helper does not block
        // and does not retry. Count the loss and carry on.
        u32 zero = 0;
        u64 *n = bpf_map_lookup_elem(&dropped, &zero);
        if (n)
            (*n)++;   // per-CPU value: no atomic needed
        return 0;
    }
    e->pid = bpf_get_current_pid_tgid() >> 32;   // upper 32 bits: process ID
    e->cpu = bpf_get_smp_processor_id();         // helper: number of the current CPU
    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
