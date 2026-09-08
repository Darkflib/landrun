package exec

import (
	"os"
	osexec "os/exec"
	"path/filepath"
	"testing"
)

func TestRunUsesPreviouslyResolvedBinary(t *testing.T) {
	resolvedBinary, err := osexec.LookPath("true")
	if err != nil {
		t.Fatalf("failed to resolve true: %v", err)
	}

	fakeBinDir := t.TempDir()
	decoyName := "landrun-exec-decoy"
	decoyPath := filepath.Join(fakeBinDir, decoyName)
	if err := os.WriteFile(decoyPath, []byte("#!/bin/sh\nexit 42\n"), 0o755); err != nil {
		t.Fatalf("failed to create decoy executable: %v", err)
	}

	cmd := osexec.Command(os.Args[0], "-test.run=^TestRunHelper$")
	cmd.Env = []string{
		"LANDRUN_EXEC_HELPER=1",
		"LANDRUN_EXEC_BINARY=" + resolvedBinary,
		"LANDRUN_EXEC_ARGV0=" + decoyName,
		"PATH=" + fakeBinDir,
	}
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("resolved executable was replaced through PATH: %v\n%s", err, string(out))
	}
}

func TestRunHelper(t *testing.T) {
	if os.Getenv("LANDRUN_EXEC_HELPER") != "1" {
		return
	}

	err := Run(
		os.Getenv("LANDRUN_EXEC_BINARY"),
		[]string{os.Getenv("LANDRUN_EXEC_ARGV0")},
		nil,
	)
	t.Fatalf("Run returned instead of executing the resolved binary: %v", err)
}
