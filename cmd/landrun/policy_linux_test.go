//go:build linux

package main

import (
	"fmt"
	"os"
	"testing"
)

func TestPolicyFileDescriptorCannotSatisfyPreserveFD(t *testing.T) {
	probe, err := os.Open("/dev/null")
	if err != nil {
		t.Fatal(err)
	}
	closedFD := int(probe.Fd())
	if err := probe.Close(); err != nil {
		t.Fatal(err)
	}

	policy := fmt.Sprintf(`{"version":1,"preserve-fd":[%d]}`, closedFD)
	path := writePolicyFile(t, policy)
	if got := run([]string{"landrun", "--policy", path, "--", "true"}); got != launcherErrorExitCode {
		t.Fatalf("run returned %d, want %d for caller-closed descriptor %d", got, launcherErrorExitCode, closedFD)
	}
}
