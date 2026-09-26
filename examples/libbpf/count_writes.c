// Minimal user-space loader for count_writes.bpf.o using libbpf.
// Usage: sudo ./count_writes [seconds]   (default 10)
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

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
    struct bpf_object *obj = bpf_object__open_file("count_writes.bpf.o", NULL);
    if (!obj) {
        fprintf(stderr, "failed to open count_writes.bpf.o\n");
        return 1;
    }
    // 2. Load it into the kernel: the verifier runs here.
    if (bpf_object__load(obj)) {
        fprintf(stderr, "failed to load BPF object (verifier or permissions)\n");
        return 1;
    }
    // 3. Attach the program to the tracepoint named in its SEC().
    struct bpf_program *prog = bpf_object__find_program_by_name(obj, "count_writes");
    struct bpf_link *link = bpf_program__attach(prog);
    if (!link) {
        fprintf(stderr, "failed to attach program\n");
        return 1;
    }

    printf("Counting write() calls per PID for %d seconds.\n", secs);
    printf("In another terminal try: sudo bpftool map dump name counts\n");
    sleep(secs);

    // 4. Read the map: iterate over every PID key and print its count.
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

    bpf_link__destroy(link);
    bpf_object__close(obj);
    return 0;
}
