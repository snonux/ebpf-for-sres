//go:build ignore

// Kernel side of 05: read() latency histogram in microseconds. Store a
// timestamp per thread on entry, subtract it on return (same as readlat.bt).
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#define SLOTS 64

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u32);    // thread id
    __type(value, u64);  // entry timestamp, ns
} start SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, SLOTS);
    __type(key, u32);
    __type(value, u64);
} hist SEC(".maps");

static __always_inline u32 log2_slot(u64 v)
{
    u32 slot = 0;
    while (v && slot < SLOTS - 1) {
        v >>= 1;
        slot++;
    }
    return slot;
}

SEC("tracepoint/syscalls/sys_enter_read")
int read_enter(void *ctx)
{
    u32 tid = (u32)bpf_get_current_pid_tgid();
    u64 ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&start, &tid, &ts, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_read")
int read_exit(void *ctx)
{
    u32 tid = (u32)bpf_get_current_pid_tgid();
    u64 *ts = bpf_map_lookup_elem(&start, &tid);
    if (!ts)
        return 0;
    u32 slot = log2_slot((bpf_ktime_get_ns() - *ts) / 1000);
    bpf_map_delete_elem(&start, &tid);
    u64 *n = bpf_map_lookup_elem(&hist, &slot);
    if (n)
        __sync_fetch_and_add(n, 1);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
