//go:build ignore

// The libbpf example from the slides: count write() calls per PID.
//
// Kept as short as on the slide. It is 01 with the PID as the key instead of
// the process name; see 01-opens-per-process/opens.bpf.c for a line-by-line
// explanation. This one object is loaded by two user-space programs in this
// directory, to compare them: main.go (Go, libbpfgo) and count_writes.c
// (plain C, libbpf).
#include "vmlinux.h"          // all kernel types, generated from BTF
#include <bpf/bpf_helpers.h>  // SEC(), map macros, bpf_*() helpers

// Hash map shared with user space: PID -> number of write() calls.
// libbpf creates it when the object is loaded.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u32);     // PID
    __type(value, u64);   // write() calls
} counts SEC(".maps");

// Attach to the entry of the write() syscall. Runs once per write(), on
// whatever CPU and in whatever process made the call.
SEC("tracepoint/syscalls/sys_enter_write")
int count_writes(void *ctx) {
    // Upper 32 bits of pid_tgid: the process ID.
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    // Pointer to this PID's counter inside the map, or NULL if there is none.
    u64 one = 1, *n = bpf_map_lookup_elem(&counts, &pid);
    if (n) __sync_fetch_and_add(n, 1);                         // atomic increment
    else   bpf_map_update_elem(&counts, &pid, &one, BPF_ANY);  // first write(): start at 1
    return 0;
}

// Required: GPL-compatible programs may use all helpers.
char LICENSE[] SEC("license") = "GPL";
