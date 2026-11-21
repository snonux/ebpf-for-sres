//go:build ignore

// Kernel side of 04: power-of-two histogram of bytes returned by read().
// Same as readsize.bt: tracepoint:syscalls:sys_exit_read /args.ret > 0/ { @bytes = hist(args.ret); }
//
// New compared with 01:
//   - an array map used as a histogram (this is what bpftrace's hist() builds)
//   - a loop, which the verifier only accepts because it is bounded
//   - a syscall-EXIT tracepoint, where the return value is available
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

// Number of histogram buckets. 64 are enough for any u64 value: one bucket
// per bit position.
#define SLOTS 64

// An array map: a fixed number of values, indexed 0..max_entries-1. All
// entries exist from the start and are zero, so a lookup with a valid index
// never has to create anything. Cheaper than a hash map.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, SLOTS);   // slot i counts values in [2^(i-1), 2^i)
    __type(key, u32);             // bucket index
    __type(value, u64);           // number of read() calls in that bucket
} hist SEC(".maps");

// Which bucket does v belong to? Count how often v can be halved: 1 -> 1,
// 2..3 -> 2, 4..7 -> 3, ... 4096..8191 -> 13. That is log2(v) + 1.
// __always_inline: the code is pasted into the caller, so this is not a
// separate BPF function that the verifier has to check on its own.
static __always_inline u32 log2_slot(u64 v)
{
    u32 slot = 0;
    while (v && slot < SLOTS - 1) {   // bounded loop: the verifier accepts it
        // "slot < SLOTS - 1" is what makes it bounded: the verifier can see
        // that the loop ends after at most 63 rounds, whatever v is. Without
        // that condition the program would be rejected. (Kernels before 5.3
        // allow no loops at all.)
        v >>= 1;
        slot++;
    }
    return slot;
}

// The exit side of read(): the syscall is done, and its return value is known.
SEC("tracepoint/syscalls/sys_exit_read")
// struct syscall_trace_exit is the record of every syscall-exit tracepoint:
// ctx->nr is the syscall number, ctx->ret the return value. For read() that
// is the number of bytes read, 0 at end of file, or a negative errno.
int read_size(struct syscall_trace_exit *ctx)
{
    if (ctx->ret <= 0)
        return 0;   // the /args.ret > 0/ filter
    u32 slot = log2_slot(ctx->ret);
    // Array lookups can still return NULL as far as the verifier knows (the
    // index could be out of range), so the check is required here too.
    u64 *n = bpf_map_lookup_elem(&hist, &slot);
    if (n)
        __sync_fetch_and_add(n, 1);   // atomic add: all CPUs share the bucket
    return 0;
}

// Why struct syscall_trace_enter/exit and not trace_event_raw_sys_enter/exit:
// RHEL 9 kernels (and so Rocky 9) widen the trace_event_raw_* types by 8 bytes,
// which shifts args/ret and makes the verifier reject the program (EACCES).
// The syscall_trace_* structs match what the kernel really passes. Same fix
// as ior and bcc (github.com/iovisor/bcc/pull/4920).
char LICENSE[] SEC("license") = "GPL";
