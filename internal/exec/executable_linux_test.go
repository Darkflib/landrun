//go:build linux

package exec

import (
	"io"
	"os"
	osexec "os/exec"
	"path/filepath"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

func TestRunFileUsesOpenedExecutable(t *testing.T) {
	target := filepath.Join(t.TempDir(), "target")
	copyExecutable(t, os.Args[0], target)

	cmd := osexec.Command(os.Args[0], "-test.run=^TestRunFileReplacementHelper$")
	cmd.Env = append(os.Environ(),
		"LANDRUN_EXEC_FD_HELPER=1",
		"LANDRUN_EXEC_FD_TARGET="+target,
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("descriptor execution followed replaced path: %v\n%s", err, out)
	}
}

func TestRunFileReplacementHelper(t *testing.T) {
	if os.Getenv("LANDRUN_EXEC_FD_HELPER") != "1" {
		return
	}
	if os.Getenv("LANDRUN_EXEC_FD_EXECUTED") == "1" {
		return
	}

	target := os.Getenv("LANDRUN_EXEC_FD_TARGET")
	file, err := OpenExecutable(target)
	if err != nil {
		t.Fatalf("failed to open target: %v", err)
	}
	defer file.Close()

	if err := os.Rename(target, target+".original"); err != nil {
		t.Fatalf("failed to move target: %v", err)
	}
	falsePath, err := osexec.LookPath("false")
	if err != nil {
		t.Fatalf("failed to find false: %v", err)
	}
	copyExecutable(t, falsePath, target)

	env := append(os.Environ(), "LANDRUN_EXEC_FD_EXECUTED=1")
	if err := RunFile(file, []string{target, "-test.run=^TestRunFileReplacementHelper$"}, env); err != nil {
		t.Fatalf("failed to execute opened target: %v", err)
	}
}

// Multi-call binaries (uutils, busybox) pick the tool from AT_EXECFN, so an
// unreplaced target must be executed by its path, not as /dev/fd/N.
func TestRunFileKeepsThePathAsExecName(t *testing.T) {
	target := filepath.Join(t.TempDir(), "target")
	copyExecutable(t, os.Args[0], target)

	cmd := osexec.Command(os.Args[0], "-test.run=^TestRunFileExecNameHelper$")
	cmd.Env = append(os.Environ(),
		"LANDRUN_EXECFN_HELPER=1",
		"LANDRUN_EXECFN_TARGET="+target,
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("exec name check failed: %v\n%s", err, out)
	}
}

func TestRunFileExecNameHelper(t *testing.T) {
	if os.Getenv("LANDRUN_EXECFN_HELPER") != "1" {
		return
	}
	target := os.Getenv("LANDRUN_EXECFN_TARGET")
	if os.Getenv("LANDRUN_EXECFN_EXECUTED") == "1" {
		if got := execFn(t); got != target {
			t.Fatalf("AT_EXECFN = %q, want %q", got, target)
		}
		return
	}
	file, err := OpenExecutable(target)
	if err != nil {
		t.Fatalf("failed to open target: %v", err)
	}
	defer file.Close()
	env := append(os.Environ(), "LANDRUN_EXECFN_EXECUTED=1")
	if err := RunFile(file, []string{target, "-test.run=^TestRunFileExecNameHelper$"}, env); err != nil {
		t.Fatalf("failed to execute opened target: %v", err)
	}
}

// execFn reads AT_EXECFN, the name the kernel recorded for this exec.
func execFn(t *testing.T) string {
	t.Helper()
	auxv, err := os.ReadFile("/proc/self/auxv")
	if err != nil {
		t.Fatal(err)
	}
	const atExecFn = 31
	word := int(unsafe.Sizeof(uintptr(0)))
	for i := 0; i+2*word <= len(auxv); i += 2 * word {
		key := *(*uintptr)(unsafe.Pointer(&auxv[i]))
		if key != atExecFn {
			continue
		}
		ptr := *(*uintptr)(unsafe.Pointer(&auxv[i+word]))
		mem, err := os.Open("/proc/self/mem")
		if err != nil {
			t.Fatal(err)
		}
		defer mem.Close()
		buf := make([]byte, 4096)
		n, _ := mem.ReadAt(buf, int64(ptr))
		name, _, found := strings.Cut(string(buf[:n]), "\x00")
		if !found {
			t.Fatal("AT_EXECFN is not NUL-terminated within 4 KiB")
		}
		return name
	}
	t.Fatal("no AT_EXECFN in auxv")
	return ""
}

func TestRunFileRejectsDirectScriptWithoutExposingDescriptor(t *testing.T) {
	script := filepath.Join(t.TempDir(), "script.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	file, err := OpenExecutable(script)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	if err := PrepareInheritedDescriptors(nil); err != nil {
		t.Fatal(err)
	}
	err = RunFile(file, []string{script}, nil)
	if err == nil || !strings.Contains(err.Error(), "invoke the interpreter explicitly") {
		t.Fatalf("direct script returned %v", err)
	}
	flags, err := unix.FcntlInt(file.Fd(), unix.F_GETFD, 0)
	if err != nil {
		t.Fatal(err)
	}
	if flags&unix.FD_CLOEXEC == 0 {
		t.Fatal("script descriptor was made inheritable")
	}
}

func copyExecutable(t *testing.T, source, target string) {
	t.Helper()
	in, err := os.Open(source)
	if err != nil {
		t.Fatalf("open %s: %v", source, err)
	}
	defer in.Close()
	out, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o755)
	if err != nil {
		t.Fatalf("create %s: %v", target, err)
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		t.Fatalf("copy %s: %v", source, err)
	}
	if err := out.Close(); err != nil {
		t.Fatalf("close %s: %v", target, err)
	}
}
