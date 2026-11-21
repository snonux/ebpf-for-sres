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

// The compiled BPF program, embedded at build time.
//
//go:embed syscalls.bpf.o
var bpfObj []byte

func main() {
	flag.Parse()
	m, err := bpfrun.Load(bpfObj, "syscalls.bpf.o", nil) // open, verify, attach
	bpfrun.Must(err)
	defer m.Close()

	fmt.Println("Counting syscalls per process name. Ctrl-C to stop.")
	// The counting happens in the kernel. This process only waits.
	bpfrun.Wait()

	// Read the result: walk over all keys of the hash map and fetch each
	// value. Both arrive as raw bytes in the kernel's layout: the key is the
	// char[16] process name, the value a u64.
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
