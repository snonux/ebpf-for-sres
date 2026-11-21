// User side of 04: wait, then read the 64 histogram slots and print them.
//
//	sudo ./readsize
package main

import (
	_ "embed"
	"encoding/binary"
	"flag"
	"fmt"
	"unsafe"

	"github.com/snonux/ebpf-for-sres/examples/internal/bpfrun"
)

// The compiled BPF program, embedded at build time.
//
//go:embed readsize.bpf.o
var bpfObj []byte

func main() {
	flag.Parse()
	m, err := bpfrun.Load(bpfObj, "readsize.bpf.o", nil)
	bpfrun.Must(err)
	defer m.Close()

	fmt.Println("Histogram of read() sizes. Ctrl-C to print.")
	// The kernel fills the histogram. This process only waits.
	bpfrun.Wait()

	// An array map is read by index. Each value comes back as 8 raw bytes, a
	// u64 in the machine's byte order.
	hist, err := m.GetMap("hist")
	bpfrun.Must(err)
	slots := make([]uint64, 64)
	for i := uint32(0); i < 64; i++ {
		if v, err := hist.GetValue(unsafe.Pointer(&i)); err == nil {
			slots[i] = binary.NativeEndian.Uint64(v)
		}
	}
	bpfrun.PrintLog2Hist("@bytes:", slots)
}
