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

//go:embed opensnoop.bpf.o
var bpfObj []byte

// event mirrors struct event in opensnoop.bpf.c byte for byte.
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
			var e event
			if err := binary.Read(bytes.NewReader(raw), binary.NativeEndian, &e); err != nil {
				continue
			}
			fmt.Printf("%-7d %-16s %s\n", e.Pid, bpfrun.CString(e.Comm[:]), bpfrun.CString(e.Filename[:]))
		}
	}
}
