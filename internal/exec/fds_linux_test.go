//go:build linux

package exec

import (
	"net"
	"os"
	osexec "os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

func TestInheritedDescriptorPolicyAcrossExec(t *testing.T) {
	if _, err := osexec.LookPath("gcc"); err != nil {
		t.Skip("gcc not found, skipping test")
	}

	checker := filepath.Join(t.TempDir(), "fd-check")
	cmd := osexec.Command("gcc", "-Wall", "-Wextra", "-Werror", "-o", checker, "testdata/fdcheck.c")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to compile descriptor checker: %v\n%s", err, string(out))
	}

	for _, tc := range []struct {
		name     string
		preserve string
		expect   string
	}{
		{name: "closed by default", expect: "0"},
		{name: "explicitly preserved", preserve: "3,4,5,6", expect: "1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			files, closeFiles := inheritedDescriptorFixtures(t)
			defer closeFiles()

			helper := osexec.Command(os.Args[0], "-test.run=^TestInheritedDescriptorExecHelper$")
			helper.ExtraFiles = files
			helper.Env = append(os.Environ(),
				"LANDRUN_FD_HELPER=1",
				"LANDRUN_FD_CHECKER="+checker,
				"LANDRUN_FD_PRESERVE="+tc.preserve,
				"LANDRUN_EXPECT_PRESERVED="+tc.expect,
			)
			if out, err := helper.CombinedOutput(); err != nil {
				t.Fatalf("descriptor policy check failed: %v\n%s", err, string(out))
			}
		})
	}
}

func TestInheritedDescriptorExecHelper(t *testing.T) {
	if os.Getenv("LANDRUN_FD_HELPER") != "1" {
		return
	}

	var preserve []int
	for _, value := range strings.Split(os.Getenv("LANDRUN_FD_PRESERVE"), ",") {
		if value == "" {
			continue
		}
		fd, err := strconv.Atoi(value)
		if err != nil {
			t.Fatalf("invalid helper descriptor %q: %v", value, err)
		}
		preserve = append(preserve, fd)
	}
	if err := PrepareInheritedDescriptors(preserve); err != nil {
		t.Fatalf("PrepareInheritedDescriptors failed: %v", err)
	}

	checker := os.Getenv("LANDRUN_FD_CHECKER")
	if err := syscall.Exec(checker, []string{checker}, os.Environ()); err != nil {
		t.Fatalf("failed to execute descriptor checker: %v", err)
	}
}

func TestValidatePreservedDescriptors(t *testing.T) {
	file, err := os.Open("/dev/null")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	fd := int(file.Fd())

	got, err := validatePreservedDescriptors([]int{fd, fd})
	if err != nil {
		t.Fatalf("valid descriptor rejected: %v", err)
	}
	if len(got) != 1 || got[0] != fd {
		t.Fatalf("duplicate descriptors were not normalized: %v", got)
	}

	for _, invalid := range []int{-1, 0, 1, 2} {
		if _, err := validatePreservedDescriptors([]int{invalid}); err == nil {
			t.Fatalf("descriptor %d should be rejected", invalid)
		}
	}
	if _, err := validatePreservedDescriptors([]int{1 << 30}); err == nil {
		t.Fatal("closed descriptor should be rejected")
	}
}

func inheritedDescriptorFixtures(t *testing.T) ([]*os.File, func()) {
	t.Helper()

	regular, err := os.CreateTemp(t.TempDir(), "regular")
	if err != nil {
		t.Fatal(err)
	}
	directory, err := os.Open(t.TempDir())
	if err != nil {
		regular.Close()
		t.Fatal(err)
	}

	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		regular.Close()
		directory.Close()
		t.Fatal(err)
	}
	listenerFile, err := listener.File()
	if err != nil {
		regular.Close()
		directory.Close()
		listener.Close()
		t.Fatal(err)
	}

	client, err := net.DialTCP("tcp4", nil, listener.Addr().(*net.TCPAddr))
	if err != nil {
		regular.Close()
		directory.Close()
		listenerFile.Close()
		listener.Close()
		t.Fatal(err)
	}
	server, err := listener.AcceptTCP()
	if err != nil {
		regular.Close()
		directory.Close()
		listenerFile.Close()
		listener.Close()
		client.Close()
		t.Fatal(err)
	}
	connectedFile, err := client.File()
	if err != nil {
		regular.Close()
		directory.Close()
		listenerFile.Close()
		listener.Close()
		client.Close()
		server.Close()
		t.Fatal(err)
	}

	files := []*os.File{regular, directory, listenerFile, connectedFile}
	closeFiles := func() {
		for _, file := range files {
			file.Close()
		}
		listener.Close()
		client.Close()
		server.Close()
	}
	return files, closeFiles
}
