//go:build ignore

// Minimal user-space loader for count_writes.bpf.o using libbpf.
// Usage: sudo ./count_writes_c [seconds]   (default 10)
//
// This is an ordinary Linux program, not BPF: it runs in user space, uses
// libc, and is compiled with a normal C compiler. Its job is the "loader"
// half of every BPF tool, in four steps: open the object, load it, attach it,
// read the map. main.go in this directory does the same four steps in Go;
// compare the two.
//
// Two header files, two layers of libbpf:
//   bpf/libbpf.h  the high-level API, bpf_object__*() and bpf_program__*():
//                 works on a whole compiled object file
//   bpf/bpf.h     thin wrappers around the bpf() syscall, bpf_map_*():
//                 works on one map through its file descriptor
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

// Look up the name of a process in /proc/<pid>/comm, to print next to the
// PID. The BPF side only stored PIDs, so this is done here, at print time. If
// the process has already exited the name is "?".
static void comm_of(__u32 pid, char *buf, size_t len)
{
    char path[64];
    snprintf(path, sizeof(path), "/proc/%u/comm", pid);
    FILE *f = fopen(path, "r");
    if (!f || !fgets(buf, len, f)) {
        snprintf(buf, len, "?");
    }
    if (f)
        fclose(f);
    buf[strcspn(buf, "\n")] = 0;
}

int main(int argc, char **argv)
{
    int secs = argc > 1 ? atoi(argv[1]) : 10;

    // 1. Open the compiled BPF object file.
    // This parses the ELF file clang produced: it finds the programs (by their
    // SEC() names), the map definitions and the BTF. Nothing is in the kernel yet.
    struct bpf_object *obj = bpf_object__open_file("count_writes.bpf.o", NULL);
    if (!obj) {
        fprintf(stderr, "failed to open count_writes.bpf.o\n");
        return 1;
    }
    // 2. Load it into the kernel: the verifier runs here.
    // libbpf creates the "counts" map, applies CO-RE relocations, and passes
    // the bytecode to the kernel with the bpf() syscall. The kernel verifies
    // it and JIT-compiles it to machine code. If the verifier rejects the
    // program, this call fails and libbpf prints the verifier's log to stderr.
    // Needs root (or CAP_BPF and CAP_PERFMON).
    if (bpf_object__load(obj)) {
        fprintf(stderr, "failed to load BPF object (verifier or permissions)\n");
        return 1;
    }
    // 3. Attach the program to the tracepoint named in its SEC().
    // Loaded is not running: until it is attached to a hook the program never
    // executes. The returned "link" represents the attachment; the program
    // stays attached as long as the link exists.
    struct bpf_program *prog = bpf_object__find_program_by_name(obj, "count_writes");
    struct bpf_link *link = bpf_program__attach(prog);
    if (!link) {
        fprintf(stderr, "failed to attach program\n");
        return 1;
    }

    // From here on the kernel runs count_writes() on every write() syscall.
    // This process just sleeps; the counting happens entirely in the kernel.
    printf("Counting write() calls per PID for %d seconds.\n", secs);
    printf("In another terminal try: sudo bpftool map dump name counts\n");
    sleep(secs);

    // 4. Read the map: iterate over every PID key and print its count.
    // User space reaches a map through a file descriptor. A hash map has no
    // "give me everything" call: bpf_map_get_next_key(fd, key, &next) returns
    // the key that follows "key" (or the first key when key is NULL), and
    // fails when there are no more. For each key, bpf_map_lookup_elem() copies
    // the value out of the kernel. Note that this is the user-space function
    // of that name (it takes an fd); the BPF-side helper is a different one.
    int map_fd = bpf_object__find_map_fd_by_name(obj, "counts");
    __u32 key, next;
    __u64 value;
    int first = 1;
    printf("\n%-8s %-16s %s\n", "PID", "COMM", "WRITES");
    while (bpf_map_get_next_key(map_fd, first ? NULL : &key, &next) == 0) {
        first = 0;
        if (bpf_map_lookup_elem(map_fd, &next, &value) == 0) {
            char comm[32];
            comm_of(next, comm, sizeof(comm));
            printf("%-8u %-16s %llu\n", next, comm, (unsigned long long)value);
        }
        key = next;
    }

    // Detach and unload. Closing the object frees the map too. This would
    // also happen automatically when the process exits: a BPF program lives
    // only as long as something holds a reference to it.
    bpf_link__destroy(link);
    bpf_object__close(obj);
    return 0;
}
