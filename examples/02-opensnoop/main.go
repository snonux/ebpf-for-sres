// User side of 02: read events from the ring buffer and print them.
//
//	sudo ./opensnoop
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
//go:embed opensnoop.bpf.o
var bpfObj []byte

// event mirrors struct event in opensnoop.bpf.c byte for byte.
// Same field order and sizes; the fields are exported so that encoding/binary
// can fill them.
type event struct {
	Pid      uint32
	Comm     [16]byte
	Filename [256]byte
}

func main() {
	flag.Parse()
	m, err := bpfrun.Load(bpfObj, "opensnoop.bpf.o", nil)
	bpfrun.Must(err)
	defer m.Close()

	// Events arrive on a Go channel. InitRingBuf connects the "events" ring
	// buffer map to the channel, and Poll starts a goroutine that waits for
	// new records (waking up at least every 300 ms) and sends each one to
	// the channel as a byte slice.
	ch := make(chan []byte, 1024)
	rb, err := m.InitRingBuf("events", ch)
	bpfrun.Must(err)
	rb.Poll(300) // a goroutine moves events from the ring buffer into ch
	defer rb.Stop()

	ctx, cancel := bpfrun.Context()
	defer cancel()
	fmt.Printf("%-7s %-16s %s\n", "PID", "COMM", "FILE")
	for {
		select {
		case <-ctx.Done():
			return
		case raw := <-ch:
			// raw holds the bytes of one struct event exactly as the kernel
			// wrote them; decode them into the Go struct.
			var e event
			if err := binary.Read(bytes.NewReader(raw), binary.NativeEndian, &e); err != nil {
				continue
			}
			fmt.Printf("%-7d %-16s %s\n", e.Pid, bpfrun.CString(e.Comm[:]), bpfrun.CString(e.Filename[:]))
		}
	}
}
