// User side of 11 in Go: the same four steps as count_writes.c (open, load,
// attach, read the map), with libbpfgo doing the C calls.
//
//	sudo ./count_writes [-duration 10s]
package main

import (
	_ "embed"
	"encoding/binary"
	"flag"
	"fmt"
	"os"
	"strings"
	"unsafe"

	"github.com/snonux/ebpf-for-sres/examples/internal/bpfrun"
)

//go:embed count_writes.bpf.o
var bpfObj []byte

func main() {
	flag.Parse()
	m, err := bpfrun.Load(bpfObj, "count_writes.bpf.o", nil) // steps 1-3
	bpfrun.Must(err)
	defer m.Close()

	fmt.Println("Counting write() calls per PID. Ctrl-C to print.")
	fmt.Println("In another terminal try: sudo bpftool map dump name counts")
	bpfrun.Wait()

	counts, err := m.GetMap("counts") // step 4
	bpfrun.Must(err)
	fmt.Printf("\n%-8s %-16s %s\n", "PID", "COMM", "WRITES")
	for it := counts.Iterator(); it.Next(); {
		key := it.Key()
		val, err := counts.GetValue(unsafe.Pointer(&key[0]))
		if err != nil {
			continue
		}
		pid := binary.NativeEndian.Uint32(key)
		fmt.Printf("%-8d %-16s %d\n", pid, comm(pid), binary.NativeEndian.Uint64(val))
	}
}

func comm(pid uint32) string {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	if err != nil {
		return "?"
	}
	return strings.TrimSpace(string(b))
}
