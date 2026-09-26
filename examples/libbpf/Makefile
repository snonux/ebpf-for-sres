# Build the libbpf example.
#   make          builds vmlinux.h, count_writes.bpf.o and the count_writes loader
#   sudo ./count_writes 10
ARCH := $(shell uname -m | sed 's/x86_64/x86/; s/aarch64/arm64/')

all: count_writes

vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@

count_writes.bpf.o: count_writes.bpf.c vmlinux.h
	clang -O2 -g -target bpf -D__TARGET_ARCH_$(ARCH) -c $< -o $@

count_writes: count_writes.c count_writes.bpf.o
	cc -O2 -Wall -o $@ count_writes.c -lbpf

clean:
	rm -f vmlinux.h count_writes.bpf.o count_writes

.PHONY: all clean
