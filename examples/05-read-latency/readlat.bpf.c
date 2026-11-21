//go:build ignore

// Kernel side of 05: read() latency histogram in microseconds. Store a
// timestamp per thread on entry, subtract it on return (same as readlat.bt).
//
// New compared with 04: two programs in one object that work together. This
// "entry/exit pair with a start map" is the standard way to measure how long
// anything takes with BPF, and 06, 07 and 13 all reuse it:
//
//   read_enter():  start[thread] = now
//   read_exit():   latency = now - start[thread]; delete start[thread];
//                  hist[log2(latency)]++
//
// The two programs never call each other. The map is their only connection.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#define SLOTS 64   // histogram buckets, one per bit of a u64 (see 04)

// Scratch map that carries the entry timestamp from read_enter() to
// read_exit(). The key is the thread ID: a thread can only be inside one
// read() at a time, so the thread ID identifies the call. (The process ID
// would not do: two threads of one process can read at the same moment.)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);   // max threads inside read() at the same time
    __type(key, u32);    // thread id
    __type(value, u64);  // entry timestamp, ns
} start SEC(".maps");

// The result: latency histogram, read by main.go. Slot i counts calls that
// took between 2^(i-1) and 2^i microseconds.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, SLOTS);
    __type(key, u32);     // bucket index
    __type(value, u64);   // number of read() calls
} hist SEC(".maps");

// Bucket for a value: how often it can be halved, i.e. log2(v) + 1. The
// "slot < SLOTS - 1" bound is what lets the verifier accept the loop (see 04).
static __always_inline u32 log2_slot(u64 v)
{
    u32 slot = 0;
    while (v && slot < SLOTS - 1) {
        v >>= 1;
        slot++;
    }
    return slot;
}

// Program 1: runs when a thread enters read().
SEC("tracepoint/syscalls/sys_enter_read")
int read_enter(void *ctx)
{
    // The lower 32 bits of pid_tgid are the thread ID (the upper 32 bits are
    // the process ID); the cast to u32 keeps only the lower half.
    u32 tid = (u32)bpf_get_current_pid_tgid();
    // Nanoseconds since boot, from a monotonic clock. Only differences between
    // two readings are meaningful, which is all we need.
    u64 ts = bpf_ktime_get_ns();
    // BPF_ANY: create the entry or overwrite an old one.
    bpf_map_update_elem(&start, &tid, &ts, BPF_ANY);
    return 0;
}

// Program 2: runs when the same thread returns from read().
SEC("tracepoint/syscalls/sys_exit_read")
int read_exit(void *ctx)
{
    u32 tid = (u32)bpf_get_current_pid_tgid();
    u64 *ts = bpf_map_lookup_elem(&start, &tid);
    if (!ts)
        // No entry: the read() started before this tool was attached, or the
        // start map was full. Nothing to measure.
        return 0;
    // Latency in ns, divided by 1000 to get microseconds, then into a bucket.
    u32 slot = log2_slot((bpf_ktime_get_ns() - *ts) / 1000);
    // Always remove the entry, otherwise the map fills up with finished calls.
    bpf_map_delete_elem(&start, &tid);
    u64 *n = bpf_map_lookup_elem(&hist, &slot);
    if (n)
        __sync_fetch_and_add(n, 1);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
