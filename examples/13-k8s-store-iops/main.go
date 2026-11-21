// storeiops: file IOPS, throughput and latency for one container's processes
// on one filesystem (default /store), printed every second.
//
// Built as a static binary (mage static) so it can be copied into any debug
// container. See README.md for the Kubernetes workflow.
//
//	storeiops -pid 1 -path /store      trace PID 1's container, its /store mount
//	storeiops -path /store             no container filter: every process
//	storeiops -pid 1 -bycomm           one line per process name and operation
package main

import (
	_ "embed"
	"encoding/binary"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"syscall"
	"time"
	"unsafe"

	bpf "github.com/aquasecurity/libbpfgo"
	"github.com/snonux/ebpf-for-sres/examples/internal/bpfrun"
)

//go:embed storeiops.bpf.o
var bpfObj []byte

var (
	pid      = flag.Int("pid", 0, "trace the container of this PID (as seen from here); 0 = all processes")
	path     = flag.String("path", "/store", "directory whose filesystem to trace, inside the target container")
	interval = flag.Duration("interval", time.Second, "print interval")
	byComm   = flag.Bool("bycomm", false, "sum up per process name instead of per PID")
	top      = flag.Int("top", 20, "print at most this many rows per interval")
)

var opNames = []string{"read", "write", "open", "fsync", "close"}

// key and stats mirror the structs in storeiops.bpf.c.
type key struct{ Pid, Op uint32 }
type stats struct {
	Count, Bytes, Errors, LatNs, MaxNs uint64
	Comm                               [16]byte
}

func main() {
	flag.Parse()
	mntns, dev := target()
	ensureTracefs()

	m, err := bpfrun.Load(bpfObj, "storeiops.bpf.o", func(m *bpf.Module) error {
		if err := m.InitGlobalVariable("target_mntns", mntns); err != nil {
			return err
		}
		return m.InitGlobalVariable("target_dev", dev)
	})
	bpfrun.Must(err)
	defer m.Close()
	statsMap, err := m.GetMap("stats")
	bpfrun.Must(err)

	ctx, cancel := bpfrun.Context()
	defer cancel()
	tick := bpfrun.Ticker(ctx, *interval)
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-tick:
			report(now, statsMap)
		}
	}
}

// target works out the mount namespace and the filesystem to filter on.
// /proc/<pid>/root/<path> is the target's /store, seen from our namespace.
func target() (mntns uint64, dev uint32) {
	root := "/"
	if *pid > 0 {
		var st syscall.Stat_t
		bpfrun.Must(syscall.Stat(fmt.Sprintf("/proc/%d/ns/mnt", *pid), &st))
		mntns = st.Ino
		root = fmt.Sprintf("/proc/%d/root", *pid)
	}
	full := filepath.Join(root, *path)
	var st, parent syscall.Stat_t
	bpfrun.Must(syscall.Stat(full, &st))
	if syscall.Stat(filepath.Dir(full), &parent) == nil && parent.Dev == st.Dev {
		fmt.Fprintf(os.Stderr, "note: %s is not a mount point, counting all I/O on the filesystem it is on\n", *path)
	}
	// User space and the kernel encode device numbers differently.
	major := uint32((st.Dev>>8)&0xfff | (st.Dev>>32)&^0xfff)
	minor := uint32(st.Dev&0xff | (st.Dev>>12)&^0xff)
	dev = major<<20 | minor
	fmt.Printf("tracing %s (dev %d:%d) mntns=%d, every %s. Ctrl-C to stop.\n", *path, major, minor, mntns, *interval)
	return mntns, dev
}

// ensureTracefs mounts tracefs if it is missing, which is the normal case in a
// container: libbpf needs it to look up tracepoint IDs.
func ensureTracefs() {
	for _, p := range []string{"/sys/kernel/tracing/events", "/sys/kernel/debug/tracing/events"} {
		if _, err := os.Stat(p); err == nil {
			return
		}
	}
	if err := syscall.Mount("tracefs", "/sys/kernel/tracing", "tracefs", 0, ""); err != nil {
		fmt.Fprintln(os.Stderr, "warning: no tracefs and cannot mount it:", err)
	}
}

type row struct {
	k key
	s stats
}

// report prints and then clears everything collected since the last tick.
func report(now time.Time, statsMap *bpf.BPFMap) {
	var rows []row
	for it := statsMap.Iterator(); it.Next(); {
		raw := it.Key()
		val, err := statsMap.GetValueAndDeleteKey(unsafe.Pointer(&raw[0]))
		if err != nil {
			continue
		}
		var r row
		r.k = key{binary.NativeEndian.Uint32(raw), binary.NativeEndian.Uint32(raw[4:])}
		r.s = decode(val)
		rows = append(rows, r)
	}
	if *byComm {
		rows = mergeByComm(rows)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].s.Count > rows[j].s.Count })

	secs := interval.Seconds()
	fmt.Printf("\n%s %7s %-16s %-6s %8s %9s %9s %9s %5s\n", now.Format("15:04:05"),
		"PID", "COMM", "OP", "IOPS", "MiB/s", "AVG_us", "MAX_us", "ERR")
	var total uint64
	for i, r := range rows {
		s := r.s
		total += s.Count
		if i >= *top {
			continue
		}
		pidCol := fmt.Sprint(r.k.Pid)
		if *byComm {
			pidCol = "-"
		}
		fmt.Printf("%8s %7s %-16s %-6s %8.0f %9.2f %9.1f %9.1f %5d\n", "", pidCol,
			bpfrun.CString(s.Comm[:]), opNames[r.k.Op], float64(s.Count)/secs,
			float64(s.Bytes)/secs/(1<<20), float64(s.LatNs)/float64(s.Count)/1e3,
			float64(s.MaxNs)/1e3, s.Errors)
	}
	fmt.Printf("%8s total %.0f IOPS\n", "", float64(total)/secs)
}

// mergeByComm sums rows with the same process name and operation (PID 0).
func mergeByComm(rows []row) []row {
	idx := map[string]int{}
	var out []row
	for _, r := range rows {
		k := fmt.Sprint(bpfrun.CString(r.s.Comm[:]), "/", r.k.Op)
		i, ok := idx[k]
		if !ok {
			idx[k] = len(out)
			out = append(out, row{k: key{0, r.k.Op}, s: stats{Comm: r.s.Comm}})
			i = len(out) - 1
		}
		o := &out[i].s
		o.Count += r.s.Count
		o.Bytes += r.s.Bytes
		o.Errors += r.s.Errors
		o.LatNs += r.s.LatNs
		o.MaxNs = max(o.MaxNs, r.s.MaxNs)
	}
	return out
}

func decode(b []byte) (s stats) {
	u := func(i int) uint64 { return binary.NativeEndian.Uint64(b[i*8:]) }
	s.Count, s.Bytes, s.Errors, s.LatNs, s.MaxNs = u(0), u(1), u(2), u(3), u(4)
	copy(s.Comm[:], b[40:56])
	return s
}
