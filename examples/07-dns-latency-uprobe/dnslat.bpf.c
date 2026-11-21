//go:build ignore

// Kernel side of 07: DNS lookup latency from a uprobe and uretprobe on
// getaddrinfo() in libc. libbpf finds libc.so.6 in /usr/lib64 (Rocky) or
// /lib/x86_64-linux-gnu (Debian/Ubuntu) and attaches to every process.
//
// New compared with 05/06: the probed function is in USER space. A uprobe is
// a breakpoint the kernel places in a binary or shared library. Because every
// dynamically linked program shares the same libc file, this one probe sees
// the name lookups of all of them: curl, python, java (if it resolves through
// glibc), sshd... No code change and no restart of the traced programs.
// The program itself still runs in the kernel, like every BPF program.
//
// The pattern is the entry/exit pair from 05, plus a ring buffer event (02)
// instead of a histogram, so each lookup is reported with its host name.
//
// Statically linked binaries (most Go programs) do not call libc's
// getaddrinfo() and are not seen.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>   // BPF_UPROBE(), BPF_URETPROBE()

// What the entry probe remembers for the return probe, per thread.
struct call {
    u64 ts;             // when getaddrinfo() was entered, ns
    const char *host;   // user-space pointer, still valid at return
};

// The record sent to user space for each finished lookup. main.go has the
// same struct in Go; the layouts must match.
struct event {
    u32 pid;
    s32 ret;         // getaddrinfo()'s return value: 0 = ok, else an EAI_* error
    u64 usecs;       // how long the lookup took
    char comm[16];   // process name
    char host[128];  // the name that was looked up
};

// In-flight calls: thread ID -> struct call. Same role as "start" in 05.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u32);           // thread id
    __type(value, struct call);
} calls SEC(".maps");

// Ring buffer for the events, 64 KiB. DNS lookups are rare compared with
// syscalls, so a small buffer is plenty.
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 64 * 1024);
} events SEC(".maps");

// "uprobe/<library or path>:<function>". libbpf resolves the library name the
// way the dynamic linker would, finds the function's address in the file, and
// asks the kernel to place the probe there for all processes.
SEC("uprobe/libc.so.6:getaddrinfo")
// int getaddrinfo(const char *node, const char *service, ...): BPF_UPROBE
// unpacks the first argument, the host name to resolve, from the registers.
int BPF_UPROBE(getaddrinfo_enter, const char *node)
{
    u32 tid = (u32)bpf_get_current_pid_tgid();   // lower 32 bits: thread ID
    // Only the POINTER to the host name is stored here. The string itself is
    // read at return time, which saves a copy for calls we never report.
    struct call c = { .ts = bpf_ktime_get_ns(), .host = node };
    bpf_map_update_elem(&calls, &tid, &c, BPF_ANY);
    return 0;
}

// The return probe fires when getaddrinfo() returns to its caller.
SEC("uretprobe/libc.so.6:getaddrinfo")
// BPF_URETPROBE gives us the function's return value as "ret".
int BPF_URETPROBE(getaddrinfo_exit, int ret)
{
    u32 tid = (u32)bpf_get_current_pid_tgid();
    struct call *c = bpf_map_lookup_elem(&calls, &tid);
    if (!c)
        return 0;   // we did not see this call start
    // Build the event directly inside the ring buffer (see 02).
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (e) {
        e->pid = bpf_get_current_pid_tgid() >> 32;   // upper 32 bits: process ID
        e->ret = ret;
        e->usecs = (bpf_ktime_get_ns() - c->ts) / 1000;   // ns -> microseconds
        bpf_get_current_comm(&e->comm, sizeof(e->comm));
        // Now copy the host name out of the process's memory. The caller still
        // owns that string while getaddrinfo() returns, so the pointer saved
        // at entry is still good.
        bpf_probe_read_user_str(&e->host, sizeof(e->host), c->host);
        bpf_ringbuf_submit(e, 0);
    }
    // If the buffer was full (e == NULL) the event is lost, but the entry is
    // removed either way so the map does not fill up.
    bpf_map_delete_elem(&calls, &tid);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
