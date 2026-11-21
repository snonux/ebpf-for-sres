//go:build ignore

// Kernel side of 03: count all syscalls per process name in a hash map.
// Same as syscalls.bt: tracepoint:raw_syscalls:sys_enter { @[comm] = count(); }
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, char[16]);   // process name (comm)
    __type(value, u64);      // number of syscalls
} counts SEC(".maps");

SEC("tracepoint/raw_syscalls/sys_enter")
int count_syscalls(void *ctx)
{
    char comm[16] = {};
    u64 one = 1, *n;

    bpf_get_current_comm(&comm, sizeof(comm));
    n = bpf_map_lookup_elem(&counts, &comm);
    if (n)
        __sync_fetch_and_add(n, 1);
    else
        bpf_map_update_elem(&counts, &comm, &one, BPF_NOEXIST);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
