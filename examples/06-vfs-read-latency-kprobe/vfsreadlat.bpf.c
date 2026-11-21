//go:build ignore

// Kernel side of 06: the same latency pattern as 05, with a kprobe and a
// kretprobe on the kernel function vfs_read(). kprobes hook kernel internals:
// the function can be renamed, inlined or change arguments in another kernel.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

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

SEC("kprobe/vfs_read")
int BPF_KPROBE(vfs_read_enter)
{
    u32 tid = (u32)bpf_get_current_pid_tgid();
    u64 ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&start, &tid, &ts, BPF_ANY);
    return 0;
}

SEC("kretprobe/vfs_read")
int BPF_KRETPROBE(vfs_read_exit)
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
