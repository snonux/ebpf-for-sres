// User side of 03: load syscalls.bpf.o, wait, then print the map like bpftrace.
//
//	sudo ./syscalls               (Ctrl-C prints the counts)
//	sudo ./syscalls -duration 5s
package main

import (
	_ "embed"
	"encoding/binary"
	"flag"
	"fmt"
	"sort"
	"unsafe"

	"github.com/snonux/ebpf-for-sres/examples/internal/bpfrun"
)

//go:embed syscalls.bpf.o
var bpfObj []byte

func main() {
	flag.Parse()
	m, err := bpfrun.Load(bpfObj, "syscalls.bpf.o", nil) // open, verify, attach
	bpfrun.Must(err)
	defer m.Close()

	fmt.Println("Counting syscalls per process name. Ctrl-C to stop.")
	bpfrun.Wait()

	counts, err := m.GetMap("counts")
	bpfrun.Must(err)
	type row struct {
		comm string
		n    uint64
	}
	var rows []row
	for it := counts.Iterator(); it.Next(); {
		key := it.Key()
		val, err := counts.GetValue(unsafe.Pointer(&key[0]))
		if err != nil {
			continue
		}
		rows = append(rows, row{bpfrun.CString(key), binary.NativeEndian.Uint64(val)})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].n < rows[j].n })
	for _, r := range rows {
		fmt.Printf("@[%s]: %d\n", r.comm, r.n)
	}
}
