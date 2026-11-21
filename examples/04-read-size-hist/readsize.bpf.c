//go:build ignore

// Kernel side of 04: power-of-two histogram of bytes returned by read().
// Same as readsize.bt: tracepoint:syscalls:sys_exit_read /args.ret > 0/ { @bytes = hist(args.ret); }
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#define SLOTS 64

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, SLOTS);   // slot i counts values in [2^(i-1), 2^i)
    __type(key, u32);
    __type(value, u64);
} hist SEC(".maps");

static __always_inline u32 log2_slot(u64 v)
{
    u32 slot = 0;
    while (v && slot < SLOTS - 1) {   // bounded loop: the verifier accepts it
        v >>= 1;
        slot++;
    }
    return slot;
}

SEC("tracepoint/syscalls/sys_exit_read")
int read_size(struct syscall_trace_exit *ctx)
{
    if (ctx->ret <= 0)
        return 0;   // the /args.ret > 0/ filter
    u32 slot = log2_slot(ctx->ret);
    u64 *n = bpf_map_lookup_elem(&hist, &slot);
    if (n)
        __sync_fetch_and_add(n, 1);
    return 0;
}

// Why struct syscall_trace_enter/exit and not trace_event_raw_sys_enter/exit:
// RHEL 9 kernels (and so Rocky 9) widen the trace_event_raw_* types by 8 bytes,
// which shifts args/ret and makes the verifier reject the program (EACCES).
// The syscall_trace_* structs match what the kernel really passes. Same fix
// as ior and bcc (github.com/iovisor/bcc/pull/4920).
char LICENSE[] SEC("license") = "GPL";
