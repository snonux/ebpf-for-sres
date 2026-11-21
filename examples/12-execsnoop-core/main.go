// User side of 12: print every exec with its parent PID.
//
//	sudo ./execsnoop
package main

import (
	"bytes"
	_ "embed"
	"encoding/binary"
	"flag"
	"fmt"

	"github.com/snonux/ebpf-for-sres/examples/internal/bpfrun"
)

// The compiled BPF program, embedded at build time.
//
//go:embed execsnoop.bpf.o
var bpfObj []byte

// event mirrors struct event in execsnoop.bpf.c.
type event struct {
	Pid, Ppid, UID uint32
	Comm           [16]byte
	Filename       [128]byte
}

func main() {
	flag.Parse()
	// The CO-RE step happens inside Load: before the program goes to the
	// kernel, libbpf reads /sys/kernel/btf/vmlinux and fills in the field
	// offsets of this kernel. Nothing in this file has to know about it.
	m, err := bpfrun.Load(bpfObj, "execsnoop.bpf.o", nil)
	bpfrun.Must(err)
	defer m.Close()

	// Ring buffer -> Go channel: Poll starts a goroutine that delivers each
	// record as a byte slice (see 02-opensnoop/main.go).
	ch := make(chan []byte, 1024)
	rb, err := m.InitRingBuf("events", ch)
	bpfrun.Must(err)
	rb.Poll(300)
	defer rb.Stop()

	ctx, cancel := bpfrun.Context()
	defer cancel()
	fmt.Printf("%-7s %-7s %-6s %-16s %s\n", "PID", "PPID", "UID", "COMM", "FILE")
	for {
		select {
		case <-ctx.Done():
			return
		case raw := <-ch:
			// Decode the kernel's bytes into the Go struct.
			var e event
			if binary.Read(bytes.NewReader(raw), binary.NativeEndian, &e) != nil {
				continue
			}
			fmt.Printf("%-7d %-7d %-6d %-16s %s\n", e.Pid, e.Ppid, e.UID, bpfrun.CString(e.Comm[:]), bpfrun.CString(e.Filename[:]))
		}
	}
}
