// User side of 10: consume events (optionally slowly) and print, every
// second, how many arrived and how many the kernel had to drop.
//
//	sudo ./drops               fast consumer: few or no drops
//	sudo ./drops -slow 1ms     slow consumer: the ring buffer overflows
package main

import (
	_ "embed"
	"encoding/binary"
	"flag"
	"fmt"
	"time"
	"unsafe"

	"github.com/snonux/ebpf-for-sres/examples/internal/bpfrun"
)

// The compiled BPF program, embedded at build time.
//
//go:embed drops.bpf.o
var bpfObj []byte

var slow = flag.Duration("slow", 0, "pretend each event takes this long to process")

func main() {
	flag.Parse()
	m, err := bpfrun.Load(bpfObj, "drops.bpf.o", nil)
	bpfrun.Must(err)
	defer m.Close()

	// Ring buffer -> Go channel (see 02-opensnoop/main.go). The channel is
	// small, so a slow loop below quickly stops draining the ring buffer.
	ch := make(chan []byte, 64)
	rb, err := m.InitRingBuf("events", ch)
	bpfrun.Must(err)
	rb.Poll(300)
	defer rb.Stop()
	dropped, err := m.GetMap("dropped")
	bpfrun.Must(err)

	ctx, cancel := bpfrun.Context()
	defer cancel()
	tick := bpfrun.Ticker(ctx, time.Second)
	var received, lastDropped uint64
	for {
		select {
		case <-ctx.Done():
			return
		case <-ch: // one event; with -slow, pretend it is expensive to handle
			received++
			if *slow > 0 {
				time.Sleep(*slow)
			}
		case <-tick:
			// Once a second: read the kernel's drop counter (key 0 of the
			// per-CPU array) and print the difference to the last reading.
			total := sumPerCPU(dropped.GetValue(unsafe.Pointer(new(uint32))))
			fmt.Printf("received %8d   dropped %8d events/s\n", received, total-lastDropped)
			received, lastDropped = 0, total
		}
	}
}

// sumPerCPU adds up a per-CPU u64 value: libbpfgo returns one 8-byte slot per CPU.
func sumPerCPU(v []byte, err error) uint64 {
	var sum uint64
	for i := 0; err == nil && i+8 <= len(v); i += 8 {
		sum += binary.NativeEndian.Uint64(v[i:])
	}
	return sum
}
