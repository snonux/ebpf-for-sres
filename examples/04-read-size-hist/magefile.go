//go:build mage

// Build and test the Go (libbpfgo) version of this example.
//
//	mage            builds ./readsize with readsize.bpf.o embedded
//	mage static     the same, as a fully static binary
//	sudo -E mage test   builds, runs it for 4s under load, checks the output
package main

import "github.com/snonux/ebpf-for-sres/examples/internal/magebpf"

const bin = "readsize"

// Default target.
var Default = Build

// Build compiles readsize.bpf.c and the Go loader.
func Build() error { return magebpf.Build(bin) }

// Static builds a fully static binary (see examples/Containerfile.static).
func Static() error { return magebpf.Static(bin) }

// Test runs the binary as root for a few seconds and checks its output.
func Test() error { return magebpf.Test(bin, "[32K, 64K)") }

// Clean removes the binary and the BPF object.
func Clean() error { return magebpf.Clean(bin) }
