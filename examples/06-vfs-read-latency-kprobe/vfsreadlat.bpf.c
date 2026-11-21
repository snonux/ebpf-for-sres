//go:build ignore

// Kernel side of 06: the same latency pattern as 05, with a kprobe and a
// kretprobe on the kernel function vfs_read(). kprobes hook kernel internals:
// the function can be renamed, inlined or change arguments in another kernel.
//
// Why bother, if 05 does the same with tracepoints? To show the difference.
// A tracepoint is a hook the kernel developers put there on purpose. A kprobe
// can be placed on almost any kernel function, including ones with no
// tracepoint nearby, but nobody promises that function still exists in the
// next kernel. vfs_read() is where read(), pread() and others meet inside the
// kernel, one layer below the syscall.
//
// Does the function exist on this kernel?  grep -w vfs_read /proc/kallsyms
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
// bpf_tracing.h provides BPF_KPROBE() and BPF_KRETPROBE(), which unpack the
// CPU registers of the probed function into normal C arguments.
#include <bpf/bpf_tracing.h>

#define SLOTS 64   // histogram buckets, one per bit of a u64 (see 04)

// Entry timestamp per thread, carried from the kprobe to the kretprobe.
// Same role as in 05.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u32);    // thread id
    __type(value, u64);  // entry timestamp, ns
} start SEC(".maps");

// Latency histogram in microseconds, read by main.go.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, SLOTS);
    __type(key, u32);     // bucket index
    __type(value, u64);   // number of vfs_read() calls
} hist SEC(".maps");

// Bucket for a value: log2(v) + 1, with a bounded loop (see 04).
static __always_inline u32 log2_slot(u64 v)
{
    u32 slot = 0;
    while (v && slot < SLOTS - 1) {
        v >>= 1;
        slot++;
    }
    return slot;
}

// "kprobe/<function>": run this program when the kernel enters vfs_read().
SEC("kprobe/vfs_read")
// BPF_KPROBE(name, args...) declares the program. A kprobe's ctx is the saved
// CPU registers (struct pt_regs); the macro hides that. We need none of
// vfs_read()'s arguments, so only the name is given. To use them you would
// write: BPF_KPROBE(vfs_read_enter, struct file *file, char *buf, size_t count)
int BPF_KPROBE(vfs_read_enter)
{
    u32 tid = (u32)bpf_get_current_pid_tgid();   // lower 32 bits: thread ID
    u64 ts = bpf_ktime_get_ns();                 // monotonic clock, ns
    bpf_map_update_elem(&start, &tid, &ts, BPF_ANY);
    return 0;
}

// "kretprobe/<function>": run when vfs_read() returns to its caller.
SEC("kretprobe/vfs_read")
// With BPF_KRETPROBE(name, type ret) the return value would be available as
// an argument; it is not needed here.
int BPF_KRETPROBE(vfs_read_exit)
{
    u32 tid = (u32)bpf_get_current_pid_tgid();
    u64 *ts = bpf_map_lookup_elem(&start, &tid);
    if (!ts)
        return 0;   // entry not seen (tool attached mid-call)
    // Elapsed ns -> microseconds -> histogram bucket.
    u32 slot = log2_slot((bpf_ktime_get_ns() - *ts) / 1000);
    bpf_map_delete_elem(&start, &tid);   // done with this call
    u64 *n = bpf_map_lookup_elem(&hist, &slot);
    if (n)
        __sync_fetch_and_add(n, 1);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
