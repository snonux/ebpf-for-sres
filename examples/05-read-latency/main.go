// User side of 05: wait, then read the latency histogram and print them.
//
//	sudo ./readlat
package main

import (
	_ "embed"
	"encoding/binary"
	"flag"
	"fmt"
	"unsafe"

	"github.com/snonux/ebpf-for-sres/examples/internal/bpfrun"
)

//go:embed readlat.bpf.o
var bpfObj []byte

func main() {
	flag.Parse()
	m, err := bpfrun.Load(bpfObj, "readlat.bpf.o", nil)
	bpfrun.Must(err)
	defer m.Close()

	fmt.Println("read() latency in microseconds. Ctrl-C to print.")
	bpfrun.Wait()

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
