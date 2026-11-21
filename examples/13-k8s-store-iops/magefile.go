//go:build mage

// Build and test storeiops.
//
//	mage                builds ./storeiops (dynamically linked, for this host)
//	mage static         fully static ./storeiops, to copy into a debug container
//	sudo -E mage test   mounts a tmpfs as a stand-in for /store, writes to it
//	                    and checks that storeiops sees exactly that I/O
package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/magefile/mage/sh"
	"github.com/snonux/ebpf-for-sres/examples/internal/magebpf"
)

const bin = "storeiops"

// Default target.
var Default = Build

// Build compiles storeiops.bpf.c and the Go loader.
func Build() error { return magebpf.Build(bin) }

// Static builds a fully static binary (see examples/Containerfile.static).
func Static() error { return magebpf.Static(bin) }

// Clean removes the binary and the BPF object.
func Clean() error { return magebpf.Clean(bin) }

// Test traces a tmpfs at /tmp/ebpf-store-test while workload.sh writes there.
func Test() error {
	if err := Build(); err != nil {
		return err
	}
	const store = "/tmp/ebpf-store-test"
	if err := os.MkdirAll(store, 0o755); err != nil {
		return err
	}
	if err := sh.Run("mountpoint", "-q", store); err != nil {
		if err := sh.RunV("mount", "-t", "tmpfs", "tmpfs", store); err != nil {
			return err
		}
		defer sh.Run("umount", store)
	}
	load := exec.Command("bash", "../workload.sh", "8")
	load.Env = append(os.Environ(), "WORKLOAD_DIR="+store)
	if err := load.Start(); err != nil {
		return err
	}
	defer load.Wait()
	// -pid of this process: same mount namespace as the workload.
	out, err := exec.Command("./"+bin, "-duration", "4s", "-path", store,
		"-pid", fmt.Sprint(os.Getpid()), "-bycomm").CombinedOutput()
	fmt.Print(string(out))
	if err != nil {
		return err
	}
	for _, want := range []string{" head ", " cat ", " write ", " read ", " open ", " close "} {
		if !strings.Contains(string(out), want) {
			return fmt.Errorf("storeiops output does not contain %q", want)
		}
	}
	if strings.Contains(string(out), " getent ") {
		return fmt.Errorf("storeiops counted getent, which never touches %s", store)
	}
	fmt.Println("PASS go/storeiops")
	return nil
}
