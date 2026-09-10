package main

import (
	"os"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func TestVersionStringIncludesBuildIdentity(t *testing.T) {
	got := versionString()
	for _, want := range []string{Version, "revision ", runtime.Version()} {
		if !strings.Contains(got, want) {
			t.Fatalf("versionString() = %q, missing %q", got, want)
		}
	}
}

func TestProcessEnvironmentVars(t *testing.T) {
	t.Setenv("LANDRUN_TEST_ENV_A", "value-a")
	os.Unsetenv("LANDRUN_TEST_ENV_MISSING")

	tests := []struct {
		name string
		in   []string
		want []string
	}{
		{
			name: "empty",
			in:   nil,
			want: []string{},
		},
		{
			name: "key equals value",
			in:   []string{"FOO=bar"},
			want: []string{"FOO=bar"},
		},
		{
			name: "key from environment",
			in:   []string{"LANDRUN_TEST_ENV_A"},
			want: []string{"LANDRUN_TEST_ENV_A=value-a"},
		},
		{
			name: "missing key omitted",
			in:   []string{"LANDRUN_TEST_ENV_MISSING"},
			want: []string{},
		},
		{
			name: "mixed",
			in:   []string{"LANDRUN_TEST_ENV_A", "CUSTOM=1", "LANDRUN_TEST_ENV_MISSING"},
			want: []string{"LANDRUN_TEST_ENV_A=value-a", "CUSTOM=1"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := processEnvironmentVars(tc.in)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got %#v want %#v", got, tc.want)
			}
		})
	}
}

func TestRunReturnsLauncherErrorForInvalidPolicy(t *testing.T) {
	for _, args := range [][]string{
		{"landrun", "--bind-tcp", "-1", "--", "true"},
		{"landrun", "--bind-tcp", "65536", "--", "true"},
		{"landrun", "--connect-tcp", "0", "--", "true"},
		{"landrun", "--connect-tcp", "131071", "--", "true"},
	} {
		if got := run(args); got != launcherErrorExitCode {
			t.Errorf("run(%q) returned %d, want %d", args, got, launcherErrorExitCode)
		}
	}
}

func TestRunReturnsLauncherErrorWhenCommandIsMissing(t *testing.T) {
	if got := run([]string{"landrun"}); got != launcherErrorExitCode {
		t.Fatalf("run returned %d, want %d", got, launcherErrorExitCode)
	}
}

func TestRunReturnsLauncherErrorForInvalidPolicyFile(t *testing.T) {
	path := writePolicyFile(t, `{"version": 1, "unknown": true}`)
	if got := run([]string{"landrun", "--policy", path, "--", "true"}); got != launcherErrorExitCode {
		t.Fatalf("run returned %d, want %d", got, launcherErrorExitCode)
	}
}

func TestRunReturnsLauncherErrorForRepeatedPolicyFile(t *testing.T) {
	path := writePolicyFile(t, `{"version": 1}`)
	if got := run([]string{"landrun", "--policy", path, "--policy", path, "--", "true"}); got != launcherErrorExitCode {
		t.Fatalf("run returned %d, want %d", got, launcherErrorExitCode)
	}
}

func TestRunReturnsLauncherErrorForEmptyPolicyPath(t *testing.T) {
	if got := run([]string{"landrun", "--policy=", "--", "true"}); got != launcherErrorExitCode {
		t.Fatalf("run returned %d, want %d", got, launcherErrorExitCode)
	}
}
