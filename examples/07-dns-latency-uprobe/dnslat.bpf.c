//go:build ignore

// Kernel side of 07: DNS lookup latency from a uprobe and uretprobe on
// getaddrinfo() in libc. libbpf finds libc.so.6 in /usr/lib64 (Rocky) or
// /lib/x86_64-linux-gnu (Debian/Ubuntu) and attaches to every process.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct call {
    u64 ts;
    const char *host;   // user-space pointer, still valid at return
};

struct event {
    u32 pid;
    s32 ret;
    u64 usecs;
    char comm[16];
    char host[128];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u32);           // thread id
    __type(value, struct call);
} calls SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 64 * 1024);
} events SEC(".maps");

SEC("uprobe/libc.so.6:getaddrinfo")
int BPF_UPROBE(getaddrinfo_enter, const char *node)
{
    u32 tid = (u32)bpf_get_current_pid_tgid();
    struct call c = { .ts = bpf_ktime_get_ns(), .host = node };
    bpf_map_update_elem(&calls, &tid, &c, BPF_ANY);
    return 0;
}

SEC("uretprobe/libc.so.6:getaddrinfo")
int BPF_URETPROBE(getaddrinfo_exit, int ret)
{
    u32 tid = (u32)bpf_get_current_pid_tgid();
    struct call *c = bpf_map_lookup_elem(&calls, &tid);
    if (!c)
        return 0;
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (e) {
        e->pid = bpf_get_current_pid_tgid() >> 32;
        e->ret = ret;
        e->usecs = (bpf_ktime_get_ns() - c->ts) / 1000;
        bpf_get_current_comm(&e->comm, sizeof(e->comm));
        bpf_probe_read_user_str(&e->host, sizeof(e->host), c->host);
        bpf_ringbuf_submit(e, 0);
    }
    bpf_map_delete_elem(&calls, &tid);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
