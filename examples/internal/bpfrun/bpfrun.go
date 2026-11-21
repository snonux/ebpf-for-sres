// Package bpfrun is the little bit of Go every example shares: load the
// embedded BPF object, attach its programs, wait, and print a histogram the
// way bpftrace does. Each example's main.go stays short enough to read on a slide.
package bpfrun

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	bpf "github.com/aquasecurity/libbpfgo"
)

// Duration is the -duration flag: 0 means run until Ctrl-C.
var Duration = flag.Duration("duration", 0, "stop after this long (default: until Ctrl-C)")

func init() {
	// libbpf prints every attach and load step at info level; keep warnings only.
	bpf.SetLoggerCbs(bpf.Callbacks{
		Log: func(level int, msg string) {
			if level <= bpf.LibbpfWarnLevel {
				fmt.Fprint(os.Stderr, msg)
			}
		},
	})
}

// Load opens the embedded BPF object (the bytes of <name>.bpf.o), lets setup
// change global variables before the verifier sees the program, loads it into
// the kernel and attaches every program to the hook named in its SEC("...").
func Load(obj []byte, name string, setup func(*bpf.Module) error) (*bpf.Module, error) {
	m, err := open(obj, name)
	if err != nil {
		return nil, fmt.Errorf("open BPF object: %w", err)
	}
	if setup != nil {
		if err := setup(m); err != nil {
			m.Close()
			return nil, err
		}
	}
	if err := m.BPFLoadObject(); err != nil { // the verifier runs here
		m.Close()
		return nil, fmt.Errorf("load BPF object (verifier or permissions, are you root?): %w", err)
	}
	if err := m.AttachPrograms(); err != nil {
		m.Close()
		return nil, fmt.Errorf("attach: %w", err)
	}
	return m, nil
}

// open is bpf.NewModuleFromBuffer, plus a fallback for hosts where raising
// RLIMIT_MEMLOCK is not allowed (some containers). Kernels since 5.11, and so
// Rocky 9, account BPF memory to the cgroup and do not need the bump at all,
// but only the file-based loader in libbpfgo lets us skip it.
func open(obj []byte, name string) (*bpf.Module, error) {
	m, err := bpf.NewModuleFromBuffer(obj, name)
	if err == nil || !strings.Contains(err.Error(), "rlimit") {
		return m, err
	}
	f, err := os.CreateTemp("", name)
	if err != nil {
		return nil, err
	}
	defer os.Remove(f.Name())
	if _, err := f.Write(obj); err != nil {
		return nil, err
	}
	f.Close()
	return bpf.NewModuleFromFileArgs(bpf.NewModuleArgs{BPFObjPath: f.Name(), BPFObjName: name, SkipMemlockBump: true})
}

// Must exits with the error message, for errors the examples cannot recover from.
func Must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

// Context is cancelled on Ctrl-C, SIGTERM or when -duration has passed.
func Context() (context.Context, context.CancelFunc) {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	if *Duration > 0 {
		ctx, cancel2 := context.WithTimeout(ctx, *Duration)
		return ctx, func() { cancel2(); cancel() }
	}
	return ctx, cancel
}

// Wait blocks until Context() is done.
func Wait() {
	ctx, cancel := Context()
	defer cancel()
	<-ctx.Done()
}

// CString turns a fixed-size, NUL-padded C char array into a Go string.
func CString(b []byte) string {
	if i := strings.IndexByte(string(b), 0); i >= 0 {
		return string(b[:i])
	}
	return string(b)
}

// PrintLog2Hist prints power-of-two buckets like bpftrace's hist(): slot i
// counts values in [2^(i-1), 2^i), slot 0 counts zeros.
func PrintLog2Hist(title string, slots []uint64) {
	last, max := -1, uint64(0)
	for i, n := range slots {
		if n > 0 {
			last = i
		}
		if n > max {
			max = n
		}
	}
	fmt.Println(title)
	if last < 0 {
		fmt.Println("(no data)")
		return
	}
	first := 0
	for first < last && slots[first] == 0 {
		first++
	}
	for i := first; i <= last; i++ {
		lo, hi := uint64(0), uint64(1)
		if i > 0 {
			lo, hi = uint64(1)<<(i-1), uint64(1)<<i
		}
		bar := strings.Repeat("@", int(slots[i]*50/max))
		fmt.Printf("[%s, %s)%*s %8d |%-50s|\n", human(lo), human(hi), 12-len(human(lo))-len(human(hi)), "", slots[i], bar)
	}
}

func human(v uint64) string {
	switch {
	case v >= 1<<30 && v%(1<<30) == 0:
		return fmt.Sprintf("%dG", v>>30)
	case v >= 1<<20 && v%(1<<20) == 0:
		return fmt.Sprintf("%dM", v>>20)
	case v >= 1<<10 && v%(1<<10) == 0:
		return fmt.Sprintf("%dK", v>>10)
	}
	return fmt.Sprint(v)
}

// Ticker returns a channel that fires every d until ctx is done (for interval output).
func Ticker(ctx context.Context, d time.Duration) <-chan time.Time {
	t := time.NewTicker(d)
	go func() { <-ctx.Done(); t.Stop() }()
	return t.C
}
