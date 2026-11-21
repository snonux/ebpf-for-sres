//go:build ignore

// Kernel side of 03: count all syscalls per process name in a hash map.
// Same as syscalls.bt: tracepoint:raw_syscalls:sys_enter { @[comm] = count(); }
//
// The code is the same as 01 (see the comments there); only the hook differs.
// 01 attaches to one syscall, this one to raw_syscalls:sys_enter, which fires
// for EVERY syscall of every process. That makes it the hottest tracepoint on
// the system and a good place to see what a BPF program costs: see
// 10-overhead-drops/overhead.sh.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

// Hash map shared with user space: process name -> number of syscalls.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, char[16]);   // process name (comm)
    __type(value, u64);      // number of syscalls
} counts SEC(".maps");

// raw_syscalls:sys_enter is the single tracepoint behind all the
// syscalls:sys_enter_<name> ones. Its record holds the syscall number and the
// six arguments; this example ignores them, so ctx stays void *.
SEC("tracepoint/raw_syscalls/sys_enter")
int count_syscalls(void *ctx)
{
    char comm[16] = {};   // zeroed: it becomes the map key
    u64 one = 1, *n;

    // Name of the process making the syscall.
    bpf_get_current_comm(&comm, sizeof(comm));
    // Pointer to its counter in the map, or NULL if there is none yet.
    n = bpf_map_lookup_elem(&counts, &comm);
    if (n)
        __sync_fetch_and_add(n, 1);   // atomic: all CPUs update the same value
    else
        bpf_map_update_elem(&counts, &comm, &one, BPF_NOEXIST);   // first one: create with 1
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
