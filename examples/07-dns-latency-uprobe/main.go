// User side of 07: print one line per getaddrinfo() call with its latency.
//
//	sudo ./dnslat     then in another shell: getent ahosts example.com
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
//go:embed dnslat.bpf.o
var bpfObj []byte

// event mirrors struct event in dnslat.bpf.c.
type event struct {
	Pid   uint32
	Ret   int32
	Usecs uint64
	Comm  [16]byte
	Host  [128]byte
}

func main() {
	flag.Parse()
	// Attaching happens inside Load: libbpf reads "uprobe/libc.so.6:getaddrinfo"
	// from the SEC() name, locates libc and the function, and places the probe.
	m, err := bpfrun.Load(bpfObj, "dnslat.bpf.o", nil)
	bpfrun.Must(err)
	defer m.Close()

	// Ring buffer -> Go channel: Poll starts a goroutine that delivers each
	// record as a byte slice (see 02-opensnoop/main.go).
	ch := make(chan []byte, 256)
	rb, err := m.InitRingBuf("events", ch)
	bpfrun.Must(err)
	rb.Poll(300)
	defer rb.Stop()

	ctx, cancel := bpfrun.Context()
	defer cancel()
	fmt.Printf("%-16s %-7s %10s %4s  %s\n", "COMM", "PID", "LATENCY", "RET", "HOST")
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
			fmt.Printf("%-16s %-7d %7d us %4d  %s\n", bpfrun.CString(e.Comm[:]), e.Pid, e.Usecs, e.Ret, bpfrun.CString(e.Host[:]))
		}
	}
}
