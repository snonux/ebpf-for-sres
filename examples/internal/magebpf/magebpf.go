// Package magebpf holds the build steps every example's magefile.go shares:
// fetch and build libbpf (through libbpfgo), dump vmlinux.h, compile the BPF C
// file with clang, then build the Go loader with the BPF object embedded.
//
// It mirrors what github.com/snonux/ior does, minus everything ior needs only
// because it is a big tool (probe generation, test gates, packaging).
package magebpf

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/magefile/mage/sh"
)

// LibbpfgoTag is the libbpfgo release the examples are built and tested with.
// It bundles libbpf 1.5.1, the same pairing ior uses.
const LibbpfgoTag = "v0.9.2-libbpf-1.5.1"

// buildDir is examples/.build, shared by all examples (one libbpf build, one vmlinux.h).
func buildDir() string {
	if d := os.Getenv("EBPF_BUILD_DIR"); d != "" {
		return d
	}
	abs, _ := filepath.Abs(filepath.Join("..", ".build"))
	return abs
}

func libbpfgoDir() string {
	if d := os.Getenv("LIBBPFGO"); d != "" {
		return d
	}
	return filepath.Join(buildDir(), "libbpfgo")
}

func exists(p string) bool { _, err := os.Stat(p); return err == nil }

// Libbpf clones libbpfgo at LibbpfgoTag and builds the static libbpf.a and its
// headers into .build/libbpfgo/output. Runs once; later builds reuse it.
func Libbpf() error {
	dir := libbpfgoDir()
	if exists(filepath.Join(dir, "output", "libbpf", "libbpf.a")) {
		return nil
	}
	if !exists(dir) {
		if err := os.MkdirAll(filepath.Dir(dir), 0o755); err != nil {
			return err
		}
		if err := sh.RunV("git", "clone", "--branch", LibbpfgoTag, "--depth", "1",
			"https://github.com/aquasecurity/libbpfgo", dir); err != nil {
			return err
		}
	}
	if err := sh.RunV("git", "-C", dir, "submodule", "update", "--init", "--recursive", "--depth", "1"); err != nil {
		return err
	}
	// Only the libbpf part of libbpfgo's Makefile: libbpf.a plus installed headers.
	return sh.RunV("make", "-C", dir, "libbpfgo-static")
}

// VmlinuxH writes .build/vmlinux.h from the running kernel's BTF. CO-RE makes
// the resulting object portable, so it does not matter much which kernel this ran on.
func VmlinuxH() error {
	out := filepath.Join(buildDir(), "vmlinux.h")
	if exists(out) {
		return nil
	}
	if err := os.MkdirAll(buildDir(), 0o755); err != nil {
		return err
	}
	hdr, err := sh.Output("bpftool", "btf", "dump", "file", "/sys/kernel/btf/vmlinux", "format", "c")
	if err != nil {
		return fmt.Errorf("bpftool btf dump (needs bpftool and /sys/kernel/btf/vmlinux): %w", err)
	}
	return os.WriteFile(out, []byte(hdr+"\n"), 0o644)
}

func bpfArch() string {
	switch runtime.GOARCH {
	case "arm64":
		return "arm64"
	default:
		return "x86"
	}
}

// BPF compiles <name>.bpf.c into <name>.bpf.o, which main.go embeds.
func BPF(name string) error {
	if err := Libbpf(); err != nil {
		return err
	}
	if err := VmlinuxH(); err != nil {
		return err
	}
	return sh.RunV("clang", "-g", "-O2", "-Wall", "-target", "bpf",
		"-D__TARGET_ARCH_"+bpfArch(),
		"-I"+buildDir(), "-I"+filepath.Join(libbpfgoDir(), "output"),
		"-c", name+".bpf.c", "-o", name+".bpf.o")
}

func goEnv() map[string]string {
	out := filepath.Join(libbpfgoDir(), "output")
	ld := filepath.Join(out, "libbpf", "libbpf.a") + " -lelf -lzstd -lz"
	return map[string]string{
		"CGO_ENABLED": "1",
		"CC":          "gcc",
		"CGO_CFLAGS":  "-I" + out + " -I" + filepath.Join(libbpfgoDir(), "libbpf", "include", "uapi"),
		"CGO_LDFLAGS": ld,
	}
}

// Build compiles the BPF object and a Go binary named after the example.
// libbpf is linked statically; glibc, libelf, zlib and zstd dynamically, so the
// binary runs on the machine it was built on and on the same distro release.
func Build(name string) error {
	if err := BPF(name); err != nil {
		return err
	}
	return sh.RunWithV(goEnv(), "go", "build", "-o", name, ".")
}

// Static builds a fully static binary: copy it to any x86_64 Linux box (or into
// a debug container) and run it. Needs libelf.a, libzstd.a, libz.a and glibc's
// libc.a, which Rocky 9 does not all ship: use the Containerfile in examples/.
func Static(name string) error {
	if err := BPF(name); err != nil {
		return err
	}
	return sh.RunWithV(goEnv(), "go", "build", "-tags", "netgo,osusergo",
		"-ldflags", "-s -w -extldflags \"-static\"", "-o", name, ".")
}

// Clean removes the example's build outputs (not the shared .build directory).
func Clean(name string) error {
	for _, f := range []string{name, name + ".bpf.o"} {
		if err := sh.Rm(f); err != nil {
			return err
		}
	}
	return nil
}

// Test builds the example, runs it for a few seconds as root while
// ../workload.sh generates file I/O, and checks that its output matches want
// (a substring). This is what run-all.sh calls for the Go version of each example.
func Test(name, want string, args ...string) error {
	if err := Build(name); err != nil {
		return err
	}
	if os.Geteuid() != 0 {
		return fmt.Errorf("mage test loads BPF programs: run it as root (sudo -E mage test)")
	}
	load := exec.Command("bash", filepath.Join("..", "workload.sh"), "8")
	if err := load.Start(); err != nil {
		return err
	}
	defer load.Wait()
	args = append([]string{"-duration", "4s"}, args...)
	cmd := exec.Command("./"+name, args...)
	start := time.Now()
	out, err := cmd.CombinedOutput()
	fmt.Print(string(out))
	if err != nil {
		return fmt.Errorf("%s failed after %s: %w", name, time.Since(start).Round(time.Millisecond), err)
	}
	if !strings.Contains(string(out), want) {
		return fmt.Errorf("%s output does not contain %q", name, want)
	}
	fmt.Printf("PASS go/%s\n", name)
	return nil
}
