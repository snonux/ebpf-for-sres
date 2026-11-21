//go:build ignore

// Kernel side of 01: count openat() calls per process name in a hash map.
// Same as opens.bt: tracepoint:syscalls:sys_enter_openat { @[comm] = count(); }
//
// START HERE. This is the smallest complete BPF program in the repository,
// and it is commented line by line. The other examples only explain what is
// new in them.
//
// How the pieces fit:
//   1. clang compiles this file to BPF bytecode (opens.bpf.o).
//   2. main.go embeds that object, hands it to the kernel (the verifier checks
//      it) and attaches count_opens() to the tracepoint named in SEC().
//   3. From then on the kernel runs count_opens() once for every openat()
//      syscall on the machine, in the context of the process that made it.
//   4. main.go reads the "counts" map and prints it.
//
// The first line, "//go:build ignore", is for the Go toolchain only: this C
// file sits in a Go package directory, and the tag tells "go build" not to
// try to compile it with cgo.

// vmlinux.h holds every type of the running kernel (structs, enums, u32, u64,
// ...), generated from the kernel's BTF by "bpftool btf dump". It replaces all
// kernel headers. There is no libc in BPF.
#include "vmlinux.h"
// bpf_helpers.h comes with libbpf: the SEC() macro, the map definition macros
// and the declarations of the bpf_*() helper functions.
#include <bpf/bpf_helpers.h>

// A map is memory that the BPF program and user space share. This anonymous
// struct is not a normal C variable: __uint() and __type() only record the
// map's properties in the object file, and libbpf creates the real map in the
// kernel when the object is loaded. bpftrace's "@[comm]" is the same thing.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);   // hash table: key -> value
    __uint(max_entries, 10240);        // fixed upper bound, memory is reserved up front
    __type(key, char[16]);   // process name (comm)
    __type(value, u64);      // number of openat() calls
} counts SEC(".maps");       // SEC(".maps") puts it where libbpf looks for maps

// SEC() names the hook. libbpf reads "tracepoint/<category>/<name>" and
// attaches the function to that tracepoint: the entry of the openat() syscall.
// Available tracepoints: sudo bpftrace -l 'tracepoint:syscalls:*'
SEC("tracepoint/syscalls/sys_enter_openat")
// ctx points to the tracepoint's record (the syscall arguments). This example
// does not look at it, so it is declared as void *. The return value of a
// tracepoint program is ignored; return 0 by convention.
int count_opens(void *ctx)
{
    // The stack is limited to 512 bytes, and the verifier insists that memory
    // is initialised before it is used as a map key: hence "= {}".
    char comm[16] = {};
    u64 one = 1, *n;

    // Helper: copy the name of the current process (what ps shows as COMM,
    // at most 15 characters plus the NUL byte) into comm.
    bpf_get_current_comm(&comm, sizeof(comm));
    // Helper: look the key up. It returns a pointer straight into the map's
    // value, or NULL if this process name has no entry yet.
    n = bpf_map_lookup_elem(&counts, &comm);
    if (n)
        // The verifier rejects the program unless n is checked for NULL first.
        // The same program runs on all CPUs at once, so the increment has to
        // be atomic: this compiles to a single locked add instruction.
        __sync_fetch_and_add(n, 1);
    else
        // First openat() of this process name: create the entry with value 1.
        // BPF_NOEXIST means "only if the key is not there yet". If another
        // CPU created it in the same instant, this call fails and one count
        // is lost, which is acceptable for a counter.
        bpf_map_update_elem(&counts, &comm, &one, BPF_NOEXIST);
    return 0;
}

// Every BPF object declares its license. Many helpers are only available to
// GPL-compatible programs, so the kernel checks this string at load time.
char LICENSE[] SEC("license") = "GPL";
