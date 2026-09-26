# eBPF for SREs: slide outline and speaker notes

Generated from the slide files in `slides/`, in deck order.

## 1. eBPF: safe little programs inside the Linux kernel

Goal of this talk: after 30 minutes you know what eBPF is, why it is safe to use on production boxes, can run a few one-liners yourself, and understand how a real tool (ior, I/O Riot NG) is built on top of it. The command at the bottom counts file opens per process name; we will come back to it.

## 2. "What is this process doing right now, and why is it slow?"

Start with the question every on-call engineer asks. Classic tools each have a blind spot. strace is the one most people know, but it works via ptrace and pauses the target on every syscall, which is why you should be careful running it on a busy production process. eBPF lets you ask new questions of a running system without restarting anything.

## 3. Small programs the kernel runs when something happens

eBPF started as a packet filter (tcpdump uses classic BPF) and grew into a general in-kernel virtual machine. Three properties matter: it is event-driven, the verifier makes it safe, and the JIT makes it fast. That combination is what makes it usable on production machines, unlike loading a custom kernel module.

## 4. From source code to a running probe

Two phases. At load time, user space compiles and loads the program and the kernel's verifier decides whether it is allowed to run; if it is, the JIT turns it into native code and it is attached to a hook. After that, every time the event fires, the program runs inside the kernel, writes into a map or ring buffer, and your user-space tool reads from there. Light boxes are user space, dark boxes are the kernel.

## 5. Where you can attach a program

For observability the top row matters most. Tracepoints are a stable interface the kernel promises to keep; kprobes can hook nearly any kernel function but may break across kernel versions. uprobes do the same for user-space code. The bottom row shows eBPF is not only for tracing: Cilium, Katran and others run networking and security in eBPF too. Try: sudo bpftrace -l 'tracepoint:syscalls:*' | wc -l to see how many syscall tracepoints your kernel has.

## 6. How the kernel and your tool share data

Maps are the only way data moves between the BPF program and user space, and between separate runs of the program. The key design decision in any eBPF tool is how much to aggregate in the kernel. Counting in a hash map is very cheap; shipping every event through a ring buffer, as ior does, gives maximum detail but costs more per event.

## 7. Why it is safe enough for production

Compare this with a kernel module: a bug in a module can panic the box, a bug in a BPF program is rejected at load time. The verifier is conservative, which is why writing BPF C sometimes feels like arguing with it. The one thing the verifier does not protect you from is cost: a cheap program attached to an event that fires a million times per second is still a million runs per second.

## 8. Try it: bpftrace one-liners

Switch to a terminal if you can and run these live. bpftrace compiles the script to BPF, loads it, and prints map contents when you press Ctrl-C. The filter is optional. Syntax note: recent bpftrace versions write tracepoint arguments as args.name; older versions use args->name.

## 9. Who is opening which files?

This is essentially opensnoop in one line. The probe fires when any process enters the openat syscall. comm is the process name, args.filename is a pointer into user memory, and str() copies the string out safely. Useful in incidents: which process keeps touching that config file, is something hammering /proc, is a service reading certificates on every request? To see available arguments: sudo bpftrace -lv tracepoint:syscalls:sys_enter_openat.

## 10. Counting and histograms, in the kernel

Both of these aggregate inside the kernel. @[comm] = count() is a hash map keyed by process name; hist() is a log2 histogram map. Nothing is printed per event, which is why these are cheap even on busy hosts. The /args.ret > 0/ part is a filter: only successful reads that returned data are counted. Lots of tiny reads in the histogram is a classic sign of missing buffering.

## 11. Latency: time from entry to return

This is the core pattern of latency tracing. The @start map holds one timestamp per thread; the exit tracepoint computes the delta and feeds a histogram in microseconds, then deletes the entry so the map does not grow. Keep this pattern in mind: it is exactly what ior does, with the same syscall tracepoints, except ior does the pairing in user space rather than in a BPF map. The kprobe variant is in the examples as 05b-vfs-read-latency-kprobe.bt.

## 12. The same idea in C with libbpf

This is the bpftrace @[pid] = count() idea written by hand. The struct with SEC(".maps") declares a hash map from PID to a counter. SEC("tracepoint/...") tells the loader where to attach the function. The program looks the PID up, increments atomically if present, inserts 1 otherwise. vmlinux.h is generated from the running kernel's BTF type info, which is what lets one compiled object run on many kernel versions (CO-RE). ior's BPF code follows exactly this structure.

## 13. Tools worth knowing before your next page

You do not have to write BPF to benefit from it. These tools ship with bcc (package names like bcc-tools or bpfcc-tools) and many also exist as bpftrace scripts. Brendan Gregg's 60-second checklist with these tools is a great on-call starting point.

## 14. How ior uses eBPF

Now a real tool. ior is a Linux-only, BPF-based I/O syscall tracer: sudo ior opens a process picker, and once you pick a PID you get a live dashboard with syscalls, files, processes, latency and flame graphs. Everything we saw so far appears in it: tracepoints, a ring buffer map, filtering in the kernel, and entry/exit pairing.

## 15. One event's journey

Follow one openat call. The kernel fires sys_enter_openat; ior's generated BPF handler checks the PID/TID filter, reserves space in the ring buffer, writes an event struct with a timestamp, the filename and the process name, and submits it. libbpfgo polls the ring buffer and hands raw bytes to a Go channel. The event loop reads the first field to know the event type, decodes it, and waits for the matching sys_exit_openat on the same thread to build a pair with a duration. The pairs feed the stats engine, the TUI tabs, flame graphs and optional Parquet recording.

## 16. The handler for openat, slightly trimmed

This is real code from internal/c/generated_tracepoints.c, with blank lines and a memset removed. Walk through it top to bottom. SEC names the tracepoint. filter() compares the current PID and TID with the configured filters. bpf_ringbuf_reserve gives a pointer directly into the shared ring buffer, so there is no extra copy. bpf_probe_read_user_str safely copies the filename from the process's memory; the verifier would reject a plain pointer dereference. Then submit makes the event visible to user space.

## 17. Filter in the kernel, configure from Go

From internal/c/filter.c, flags.h and internal/bpfsetup.go. The globals are declared const volatile: const lets the verifier treat them as constants and prune dead branches, volatile stops the compiler from optimising them away. libbpfgo's InitGlobalVariable writes the values into the object's read-only data section before BPFLoadObject hands it to the kernel. The payoff: when you trace one PID, events from every other process are discarded in a few instructions and never touch the ring buffer.

## 18. Generated from the kernel, not hand-written

Writing 234 nearly identical handlers by hand would be a copy-paste bug factory. Instead, mage generate reads the tracepoint format files from the running kernel, classifies each syscall by its argument names (does it take an fd, a filename, a pathname, two names like rename?), and emits the C handlers, Go structs that mirror the C structs byte for byte, and the list of tracepoints to attach. Return values are also classified as read, write or transfer so ior can count bytes. Generator source: internal/generate/.

## 19. From embedded object to live probes

This is setupBPFModule in internal/ior_bpfsetup.go. Note the order: maps are resized and globals set before BPFLoadObject, because after loading they are fixed. Attaching goes through a probe manager, which lets you toggle individual syscalls on and off at runtime from the TUI (the o key) and tolerates tracepoints that do not exist on older kernels by logging and skipping them. If the BPF object fails the verifier, ior fails at the load object stage with the verifier's log.

## 20. Turning two events into one measurement

From internal/event/pair.go. The kernel side stays tiny and stateless: it never tracks in-flight syscalls. Go keeps the last enter event per thread, and when the exit arrives it builds a Pair with Duration (exit minus enter on the same thread) and DurationToPrev (the gap since that thread's previous syscall ended). Timestamps come from bpf_ktime_get_boot_ns; ior guards against cross-CPU clock skew by clamping negative deltas to zero. Compare this with the bpftrace latency one-liner, which did the pairing in a BPF map.

## 21. Design choices worth copying

If you ever build your own eBPF tool, these are good defaults. The ring buffer (BPF_MAP_TYPE_RINGBUF, kernel 5.8 and later) replaced the older per-CPU perf buffer for most use cases. Keeping the BPF side dumb and doing analysis in a normal language is a pattern you will see in many production tools.

## 22. Before you run it on a production box

Practical checklist. Start with a short -duration and a PID filter, watch the host's CPU while tracing, and prefer aggregation over per-event output on hot paths. Most modern distributions ship BTF-enabled kernels (RHEL 8.2+, Ubuntu 20.10+, recent Debian and Fedora), but check before an incident, not during one.

## 23. Start small, this week

Leave people with something concrete. Listing probes is harmless and shows how much is available. For ior, see the tutorial in docs/tutorial/tutorial.md in the repository, and the blog series linked from the README. Questions.
