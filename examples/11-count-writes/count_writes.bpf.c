//go:build ignore

// The libbpf example from the slides: count write() calls per PID.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u32);     // PID
    __type(value, u64);   // write() calls
} counts SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_write")
int count_writes(void *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 one = 1, *n = bpf_map_lookup_elem(&counts, &pid);
    if (n) __sync_fetch_and_add(n, 1);
    else   bpf_map_update_elem(&counts, &pid, &one, BPF_ANY);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
