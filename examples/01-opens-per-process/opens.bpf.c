//go:build ignore

// Kernel side of 01: count openat() calls per process name in a hash map.
// Same as opens.bt: tracepoint:syscalls:sys_enter_openat { @[comm] = count(); }
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, char[16]);   // process name (comm)
    __type(value, u64);      // number of openat() calls
} counts SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_openat")
int count_opens(void *ctx)
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
