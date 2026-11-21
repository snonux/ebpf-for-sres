// User side of 06: same as 05, for vfs_read() via kprobes and print them.
//
//	sudo ./vfsreadlat
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
//go:embed vfsreadlat.bpf.o
var bpfObj []byte

func main() {
	flag.Parse()
	m, err := bpfrun.Load(bpfObj, "vfsreadlat.bpf.o", nil)
	bpfrun.Must(err)
	defer m.Close()

	fmt.Println("vfs_read() latency in microseconds (kprobe). Ctrl-C to print.")
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
	bpfrun.PrintLog2Hist("@usecs:", slots)
}
